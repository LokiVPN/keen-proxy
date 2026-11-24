package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/dnsfront"
	"github.com/ordo-systems/keen-proxy/internal/domaincache"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// observeDomain keeps device DNS answers for names that fill a DNS fallback
// set of the applied configuration: own lists and enabled provider domain
// rules. Provider names are learned only this way, never resolved by the
// daemon (see refreshDomainNames). It runs on DNS goroutines without d.mu.
func (d *Daemon) observeDomain(name string, m *dns.Msg) {
	name = domaincache.Normalize(name)
	if names := d.publishedDNSNames(); names != nil && names.Observed(name) {
		d.domains.Observe(name, m, "observed")
	}
}

// domainRecords filters fresh cache records against the published DNS names.
func (d *Daemon) domainRecords() []domaincache.Record {
	out := []domaincache.Record{}
	names := d.publishedDNSNames()
	if names == nil {
		return out
	}
	for _, r := range d.domains.Snapshot(nil) {
		if names.Observed(r.Name) {
			out = append(out, r)
		}
	}
	return out
}

// dnsNamesState is the DNS names published to DNS goroutines with the
// configuration and provider rules they were built from.
type dnsNamesState struct {
	cfg   *model.Config
	rules *compile.ProviderRules
	names *compile.DNSNames
}

// dnsNamesLocked returns the DNS names of the applied configuration and
// provider rules, building and publishing them only when either changed.
// Both are replaced on change and never modified, so pointers identify them.
func (d *Daemon) dnsNamesLocked() *compile.DNSNames {
	var rules *compile.ProviderRules
	if applied := d.subscriptions.states[providerRulesSource(d.cfg)].snapshot.Rules; applied != nil {
		rules = applied.Built
	}
	if s := d.dnsNames.Load(); s != nil && s.cfg == d.cfg && s.rules == rules {
		return s.names
	}
	names := compile.NewDNSNames(d.cfg, d.providerRulesLocked())
	d.dnsNames.Store(&dnsNamesState{cfg: d.cfg, rules: rules, names: names})
	return names
}

// publishedDNSNames returns the DNS names for readers without d.mu, or nil
// before the first compilation.
func (d *Daemon) publishedDNSNames() *compile.DNSNames {
	if s := d.dnsNames.Load(); s != nil {
		return s.names
	}
	return nil
}

// providerBlocked reports whether a provider block rule answers name locally
// for the device at client. Provider rules route only split policies, so
// other devices get the real answer. It runs on DNS goroutines and reads
// only published state, which changes without a DNS restart.
func (d *Daemon) providerBlocked(name string, client netip.Addr) bool {
	split, names := d.split.Load(), d.publishedDNSNames()
	return split != nil && names != nil && split.Contains(client) && names.ProviderBlocked(name)
}

func recordsMap(records []domaincache.Record) map[string][]string {
	out := map[string][]string{}
	for _, r := range records {
		for _, a := range r.Addresses {
			out[r.Name] = append(out[r.Name], a.IP)
		}
	}
	return out
}

// flushDomains serializes with Apply, preventing stale writes after group edits.
func (d *Daemon) flushDomains() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil {
		return
	}
	// Nothing refreshes provider names: drop their expired records so they do
	// not fill the cache that every flush reads.
	names := d.dnsNamesLocked()
	d.domains.DropExpired(func(name string) bool { return !names.InGroups(name) })
	d.writeDNSLocked()
	if d.domainError == "" {
		d.cleanDNSFilesLocked()
	}
}

// writeDNSLocked writes changed DNS fallback sets and records write progress while d.mu is held.
func (d *Daemon) writeDNSLocked() {
	sets := d.dnsNamesLocked().RuleSets(recordsMap(d.domainRecords()))
	fingerprint, _ := json.Marshal(sets)
	if bytes.Equal(fingerprint, d.domainFingerprint) && d.domainError == "" {
		return
	}
	for name, raw := range sets {
		if err := writeFile(filepath.Join(d.opt.RuleSetDir, name), raw, 0o644); err != nil {
			d.domainError = err.Error()
			return
		}
	}
	d.domainFingerprint = fingerprint
	d.domainError = ""
}

// domainGeneration cancels in-flight refreshes when the applied configuration changes.
type domainGeneration struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// resetDomainGeneration publishes a fresh refresh lifetime and cancels the previous one.
func (d *Daemon) resetDomainGeneration() {
	ctx, cancel := context.WithCancel(context.Background())
	old := d.domainGeneration.Swap(&domainGeneration{ctx, cancel})
	if old != nil {
		old.cancel()
	}
}

// RefreshDomains resolves up to 100 names with bounded concurrency and writes
// the changed DNS rule sets. Names must belong to the live configuration.
func (d *Daemon) RefreshDomains(ctx context.Context, names []string) error {
	if g := d.domainGeneration.Load(); g != nil {
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(g.ctx, cancel)
		defer stop()
		ctx = cctx
	}

	if len(names) == 0 || len(names) > 100 {
		return fmt.Errorf("between 1 and 100 domains required")
	}
	cfg := d.live.Load()
	if cfg == nil {
		return fmt.Errorf("daemon is not running")
	}
	matcher := compile.NewDomainMatcher(cfg)
	clean := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		e, err := model.ParseEntry(name)
		if err != nil || e.Kind != model.EntryDomain {
			return fmt.Errorf("invalid domain: %s", name)
		}
		if !matcher.Match(e.Domain) {
			return fmt.Errorf("domain is not in the applied list: %s", e.Domain)
		}
		if !seen[e.Domain] {
			clean = append(clean, e.Domain)
			seen[e.Domain] = true
		}
	}
	cache := d.domains
	dnsCfg := d.dnsConfig(cfg.DNS)
	dnsCfg.Timeout = 3 * time.Second
	resolver := dnsfront.New(dnsCfg)
	defer resolver.CloseIdle()
	var wg sync.WaitGroup
	for _, name := range clean {
		if d.live.Load() != cfg {
			wg.Wait()
			return fmt.Errorf("configuration changed")
		}
		select {
		case d.domainSlots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-d.domainSlots }()
			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(name), dns.TypeA)
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			resp := resolver.ResolveRaw(qctx, q)
			if resp.Rcode != dns.RcodeSuccess || resp.Truncated {
				cache.SetError(name, "DNS: "+dns.RcodeToString[resp.Rcode])
				return
			}
			cache.Observe(name, resp, "resolved")
		}(name)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	d.flushDomains()
	return nil
}

// runDomains flushes cache expiry each second and schedules nonoverlapping refresh
// batches with a minimum retry interval.
func (d *Daemon) runDomains(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	busy := make(chan struct{}, 1)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		d.flushDomains()
		select {
		case busy <- struct{}{}:
		default:
			continue
		}
		go func() {
			defer func() { <-busy }()
			cfg := d.live.Load()
			if cfg == nil {
				return
			}
			names := refreshDomainNames(cfg, d.domainRecords(), time.Now())
			existing := map[string]domaincache.Record{}
			for _, r := range d.domainRecords() {
				existing[r.Name] = r

			}
			due := []string{}
			now := time.Now()
			for _, name := range names {
				r := existing[name]
				if now.Sub(r.AttemptedAt) < 30*time.Second {
					continue
				}
				fresh := false
				for _, a := range r.Addresses {
					if a.ExpiresAt.After(now.Add(5 * time.Second)) {
						fresh = true
						break
					}
				}
				if !fresh {
					due = append(due, name)
				}
				if len(due) == 100 {
					break
				}
			}
			if len(due) > 0 {
				_ = d.RefreshDomains(ctx, due)
			}
		}()
	}
}
func containsName(names []string, name string) bool {
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// refreshDomainNames keeps the configured roots of own lists and their recently
// observed subdomains warm; service refreshes do not count as device use.
// Provider names are never resolved here: they fill DNS fallback sets only
// from answers devices received.
func refreshDomainNames(cfg *model.Config, records []domaincache.Record, now time.Time) []string {
	names := compile.DomainNames(cfg)
	matcher := compile.NewDomainMatcher(cfg)
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	for _, r := range records {
		if matcher.Match(r.Name) && !seen[r.Name] && !r.ObservedAt.IsZero() && now.Sub(r.ObservedAt) < 10*time.Minute {
			names = append(names, r.Name)
			seen[r.Name] = true
		}
	}
	return names
}

// domainConflicts identifies cached IPs shared by distinct group rule-sets.
func domainConflicts(cfg *model.Config, records []domaincache.Record) map[string][]string {
	out := map[string][]string{}
	if cfg == nil {
		return out
	}
	groups := map[string]map[string]bool{}
	for _, g := range cfg.Groups {
		if g.Disabled {
			continue
		}
		if g.IsGeo() {
			continue
		}
		m := compile.NewDomainMatcher(&model.Config{Groups: []model.Group{g}})
		for _, r := range records {
			if !m.Match(r.Name) {
				continue
			}
			for _, a := range r.Addresses {
				if groups[a.IP] == nil {
					groups[a.IP] = map[string]bool{}
				}
				groups[a.IP][compile.DomainTag(g)] = true
				out[a.IP] = appendUnique(out[a.IP], g.Name+" · "+r.Name)
			}
		}
	}
	for ip := range out {
		if len(groups[ip]) < 2 {
			delete(out, ip)
		}
	}
	return out
}
func appendUnique(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

// dnsRouteNote explains potential DNS-derived routing for connection journal entries.
func dnsRouteNote(cfg *model.Config, records []domaincache.Record, raw, ip string) string {
	if cfg == nil || !strings.Contains(raw, "dns-") {
		return ""
	}
	names := []string{}
	for _, g := range cfg.Groups {
		if g.Disabled {
			continue
		}
		if !strings.Contains(raw, compile.DomainTag(g)) {
			continue
		}
		m := compile.NewDomainMatcher(&model.Config{Groups: []model.Group{g}})
		for _, r := range records {
			if !m.Match(r.Name) {
				continue
			}
			for _, a := range r.Addresses {
				if a.IP == ip {
					names = appendUnique(names, r.Name)
				}
			}
		}
	}
	sort.Strings(names)
	if len(names) > 4 {
		names = append(names[:4], "…")
	}
	note := " · DNS: " + strings.Join(names, ", ")
	if len(domainConflicts(cfg, records)[ip]) > 1 {
		note += " · ambiguous IP, using group order"
	}
	return note
}

// Called after Apply/rollback is finished, never while the old engine still uses its files.
func (d *Daemon) cleanDNSFilesLocked() {
	keep := d.dnsNamesLocked().RuleSets(nil)
	entries, err := os.ReadDir(d.opt.RuleSetDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, "dns-") && strings.HasSuffix(name, ".json") {
			if _, ok := keep[name]; !ok {
				if err := os.Remove(filepath.Join(d.opt.RuleSetDir, name)); err != nil && !os.IsNotExist(err) {
					d.log.Warn("failed to remove stale DNS rule set", "err", err)
				}
			}
		}
	}
}
