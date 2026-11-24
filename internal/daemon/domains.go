package daemon

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
// daemon (see refreshDomainNames), so their records are spare: they give way
// to own-list records in a full cache and leave once their answers expire.
// It runs on DNS goroutines without d.mu.
func (d *Daemon) observeDomain(name string, m *dns.Msg) {
	name = domaincache.Normalize(name)
	if names := d.publishedDNSNames(); names != nil && names.Observed(name) {
		d.domains.Observe(name, m, "observed", !names.InGroups(name))
	}
}

// holdsAddress selects the cache records with ip among their addresses.
func holdsAddress(ip string) func(domaincache.Record) bool {
	return func(r domaincache.Record) bool {
		return slices.ContainsFunc(r.Addresses, func(a domaincache.Address) bool { return a.IP == ip })
	}
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

// dnsFiles records the dns-* rule-set files as the daemon last wrote them,
// so it writes them only when an answer or the DNS names changed and
// rewrites only the files whose contents changed, without reading them back.
type dnsFiles struct {
	names    *compile.DNSNames // the names of the last complete write
	answers  uint64            // the cache generation of the last complete write
	contents map[string][]byte // by file name, as written
	cleaned  *compile.DNSNames // the names whose stale files were removed
}

// flushDomains brings the DNS fallback sets up to date once a second. It
// serializes with Apply, preventing stale writes after group edits.
func (d *Daemon) flushDomains() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil {
		return
	}
	d.writeDNSLocked()
	if d.domainError == "" && d.dnsFiles.cleaned != d.dnsFiles.names {
		d.cleanDNSFilesLocked()
	}
}

// writeDNSLocked writes the DNS fallback sets of the published names from
// the cache's answers while d.mu is held. Nothing is built while neither
// changed since the last complete write, and only changed files are written.
func (d *Daemon) writeDNSLocked() {
	names, f := d.dnsNamesLocked(), &d.dnsFiles
	if d.domainError == "" && f.names == names && f.answers == d.domains.Generation() {
		return
	}
	answers, generation := d.domains.Addresses()
	sets := names.RuleSets(answers)
	if f.contents == nil {
		f.contents = make(map[string][]byte, len(sets))
	}
	for name, raw := range sets {
		if bytes.Equal(f.contents[name], raw) {
			continue
		}
		if err := replaceFile(filepath.Join(d.opt.RuleSetDir, name), raw, 0o644); err != nil {
			d.domainError = err.Error()
			return
		}
		f.contents[name] = raw
	}
	maps.DeleteFunc(f.contents, func(name string, _ []byte) bool { return sets[name] == nil })
	f.names, f.answers = names, generation
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
			cache.Observe(name, resp, "resolved", false)
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
			// Spare records belong to names nothing refreshes.
			records := d.domains.Snapshot(func(r domaincache.Record) bool { return !r.Spare })
			now := time.Now()
			names := refreshDomainNames(cfg, records, now)
			existing := make(map[string]domaincache.Record, len(records))
			for _, r := range records {
				existing[r.Name] = r
			}
			due := []string{}
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

// dnsRouteNote names, for a connection journal entry, the observed names
// behind a DNS fallback route of an own list: the names of the groups raw
// matched whose answers held ip. holding returns the cache records that hold
// ip; it is called only for such routes, so provider DNS sets, whose names
// the journal does not explain, never read the cache. Without names there
// is no note.
func dnsRouteNote(cfg *model.Config, raw, ip string, holding func() []domaincache.Record) string {
	if cfg == nil || !strings.Contains(raw, "dns-") {
		return ""
	}
	var groups []model.Group
	for _, g := range cfg.Groups {
		if !g.Disabled && strings.Contains(raw, compile.DomainTag(g)) {
			groups = append(groups, g)
		}
	}
	if len(groups) == 0 {
		return ""
	}
	records, holds := holding(), holdsAddress(ip)
	names := []string{}
	for _, g := range groups {
		m := compile.NewDomainMatcher(&model.Config{Groups: []model.Group{g}})
		for _, r := range records {
			if m.Match(r.Name) && holds(r) {
				names = appendUnique(names, r.Name)
			}
		}
	}
	if len(names) == 0 {
		return ""
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

// cleanDNSFilesLocked removes the dns-* files the last complete write did not
// produce, once per change of the DNS names. It runs after Apply or rollback
// is finished, never while the old engine still uses its files.
func (d *Daemon) cleanDNSFilesLocked() {
	entries, err := os.ReadDir(d.opt.RuleSetDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, "dns-") && strings.HasSuffix(name, ".json") {
			if _, ok := d.dnsFiles.contents[name]; !ok {
				if err := os.Remove(filepath.Join(d.opt.RuleSetDir, name)); err != nil && !os.IsNotExist(err) {
					d.log.Warn("failed to remove stale DNS rule set", "err", err)
				}
			}
		}
	}
	d.dnsFiles.cleaned = d.dnsFiles.names
}
