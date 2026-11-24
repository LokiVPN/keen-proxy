package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/domaincache"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// fullCache is the number of provider names that fill the DNS cache next to
// the own name providerNamesDaemon observes.
const fullCache = 4096 - 1

// providerNamesDaemon returns a daemon whose applied configuration has one
// own list and four provider domain rules, with one own name and then n
// provider names observed. The cache uses now, or the real clock when now is
// nil. It publishes the DNS names and flushes as Apply does.
func providerNamesDaemon(tb testing.TB, n int, now func() time.Time) *Daemon {
	tb.Helper()
	d := New(Options{RuleSetDir: tb.TempDir()})
	if now != nil {
		d.domains = domaincache.New(now)
	}
	cfg := &model.Config{
		Subscriptions: []subscription.Source{{ID: "prov", URL: "https://provider.example/s"}},
		ProviderRules: &model.ProviderRulesSettings{Source: "prov"},
		Groups:        []model.Group{{Name: "Own", Target: model.TargetDirect, Entries: []string{"own.example"}}},
	}
	rules := compile.ProviderRules{RouteOrder: "block-direct-proxy", GlobalProxy: true}
	for i := range 4 {
		action := []string{"direct", "proxy"}[i%2]
		rules.Rules = append(rules.Rules, compile.ProviderRule{
			Key: fmt.Sprintf("%s:geosite:c%d", action, i), Action: action, Kind: "site",
			Source: fmt.Sprintf("geosite:c%d", i), Suffix: []string{fmt.Sprintf("c%d.example", i)},
		})
	}
	d.cfg = cfg
	d.live.Store(cfg)
	d.subscriptions.states = map[string]appliedSubscription{"prov": {snapshot: subscriptionSnapshot{Rules: &rulesSnapshot{Built: &rules}}}}
	d.flushDomains()
	d.observeDomain("www.own.example.", answerA("www.own.example.", 300, net.IPv4(198, 51, 100, 1)))
	for i := range n {
		name := fmt.Sprintf("n%d.c%d.example.", i, i%4)
		d.observeDomain(name, answerA(name, 300, net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))))
	}
	d.flushDomains()
	return d
}

// answerA is a device's answer for name with one address per ip.
func answerA(name string, ttl uint32, ips ...net.IP) *dns.Msg {
	m := new(dns.Msg)
	for _, ip := range ips {
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: ip})
	}
	return m
}

// dnsSetFile returns the path of the DNS fallback set with tag.
func dnsSetFile(d *Daemon, tag string) string {
	return filepath.Join(d.opt.RuleSetDir, tag+".json")
}

// dnsFileHolding returns the path of the only DNS fallback set of d that
// holds address.
func dnsFileHolding(t *testing.T, d *Daemon, address string) string {
	t.Helper()
	found := dnsFilesWith(t, d, `"`+address+`/32"`)
	if len(found) != 1 {
		t.Fatalf("%s is in DNS sets %v", address, found)
	}
	return filepath.Join(d.opt.RuleSetDir, found[0])
}

func fileHolds(t *testing.T, path, text string) bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(raw), text)
}

func fileInfo(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// The once-a-second flush does no work until an answer changes an address
// or an address expires, and then rewrites only the files whose contents
// changed.
func TestDNSFlushFollowsChangesOnly(t *testing.T) {
	now := time.Now()
	d := providerNamesDaemon(t, fullCache, func() time.Time { return now })
	if n := testing.AllocsPerRun(20, d.flushDomains); n != 0 {
		t.Fatalf("a flush without a change cost %v allocations", n)
	}
	own := dnsSetFile(d, compile.DomainTag(d.cfg.Groups[0]))
	c0, c1 := dnsFileHolding(t, d, "10.0.0.0"), dnsFileHolding(t, d, "10.0.0.1") // n0.c0 and n1.c1
	before := map[string]os.FileInfo{own: fileInfo(t, own), c0: fileInfo(t, c0), c1: fileInfo(t, c1)}

	// The same answer again changes nothing.
	d.observeDomain("n0.c0.example.", answerA("n0.c0.example.", 300, net.IPv4(10, 0, 0, 0)))
	if n := testing.AllocsPerRun(20, d.flushDomains); n != 0 {
		t.Fatalf("a flush after a repeated answer cost %v allocations", n)
	}

	d.observeDomain("n0.c0.example.", answerA("n0.c0.example.", 300, net.IPv4(203, 0, 113, 1)))
	d.observeDomain("n1.c1.example.", answerA("n1.c1.example.", 5, net.IPv4(203, 0, 113, 2)))
	d.flushDomains()
	if !fileHolds(t, c0, `"203.0.113.1/32"`) || !fileHolds(t, c1, `"203.0.113.2/32"`) {
		t.Fatal("new addresses did not reach their sets")
	}
	if !os.SameFile(before[own], fileInfo(t, own)) {
		t.Error("the own list's set was rewritten without a change")
	}
	if os.SameFile(before[c0], fileInfo(t, c0)) {
		t.Error("the changed set was not replaced")
	}

	now = now.Add(4 * time.Second)
	d.flushDomains()
	if !fileHolds(t, c1, `"203.0.113.2/32"`) {
		t.Fatal("an address left before its answer expired")
	}
	now = now.Add(2 * time.Second)
	d.flushDomains()
	if fileHolds(t, c1, `"203.0.113.2/32"`) {
		t.Fatal("an expired address stayed in its set")
	}
}

// Provider names fill the cache only with records that give way to own-list
// records: the oldest own subdomain survives any number of provider names.
func TestProviderNamesDoNotEvictOwnListRecords(t *testing.T) {
	now := time.Now()
	d := providerNamesDaemon(t, 0, func() time.Time { return now })
	for i := range 2 * 4096 {
		now = now.Add(time.Millisecond)
		name := fmt.Sprintf("m%d.c%d.example.", i, i%4)
		d.observeDomain(name, answerA(name, 300, net.IPv4(10, 1, byte(i>>8), byte(i))))
	}
	d.flushDomains()
	if !slices.Contains(observedNames(d), "www.own.example") {
		t.Fatal("provider names evicted an own-list record")
	}
	if !fileHolds(t, dnsSetFile(d, compile.DomainTag(d.cfg.Groups[0])), `"198.51.100.1/32"`) {
		t.Fatal("the own list's set lost its address")
	}
}

func TestApplyReclassifiesCachedProviderNames(t *testing.T) {
	d, cfg, _ := newRulesTestDaemon(t)
	now := time.Now()
	d.domains = domaincache.New(func() time.Time { return now })
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}

	const promoted = "www.selected.direct.example."
	d.observeDomain(promoted, answerA(promoted, 300, net.IPv4(203, 0, 113, 1)))
	for i := range fullCache {
		now = now.Add(time.Millisecond)
		name := fmt.Sprintf("n%d.direct.example.", i)
		d.observeDomain(name, answerA(name, 300, net.IPv4(10, 0, byte(i>>8), byte(i))))
	}

	next := cfg.Clone()
	own := model.Group{Name: "Own", Target: model.TargetDirect, Entries: []string{"selected.direct.example"}}
	next.Groups = append(next.Groups, own)
	if err := d.Apply(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	path := dnsSetFile(d, compile.DomainTag(own))
	if !fileHolds(t, path, `"203.0.113.1/32"`) {
		t.Fatal("Apply did not use the previously observed address in the new list")
	}

	now = now.Add(time.Millisecond)
	const newest = "new.direct.example."
	d.observeDomain(newest, answerA(newest, 300, net.IPv4(203, 0, 113, 2)))
	d.flushDomains()
	if !fileHolds(t, path, `"203.0.113.1/32"`) {
		t.Error("a new provider answer evicted the address in the new own list")
	}
	names := observedNames(d)
	if !slices.Contains(names, domaincache.Normalize(newest)) || slices.Contains(names, "n0.direct.example") {
		t.Error("the newest provider answer should replace the oldest remaining provider-only answer")
	}
}

func TestProviderObservationRefreshesAfterJoiningOwnList(t *testing.T) {
	for _, tc := range []struct {
		name string
		ttl  uint32
		race bool
	}{
		{name: "expired after Apply", ttl: 5},
		{name: "answer used previous names", ttl: 36, race: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, cfg, _ := newRulesTestDaemon(t)
			cfg.DNS.Upstreams = []string{dnsUpstream(t, "198.51.100.7")}
			now := time.Now().Add(-31 * time.Second)
			d.domains = domaincache.New(func() time.Time { return now })
			if err := d.Apply(t.Context(), cfg); err != nil {
				t.Fatal(err)
			}
			const name = "www.direct.example"
			answer := answerA(dns.Fqdn(name), tc.ttl, net.IPv4(203, 0, 113, 7))
			d.observeDomain(name, answer)

			next := cfg.Clone()
			next.Groups = append(next.Groups, model.Group{Name: "Own", Target: model.TargetDirect, Entries: []string{"direct.example"}})
			if err := d.Apply(t.Context(), next); err != nil {
				t.Fatal(err)
			}
			if tc.race {
				// A DNS goroutine that read the previous names can store its answer after Apply.
				d.domains.Observe(name, answer, "observed", true)
			}
			now = now.Add(32 * time.Second)

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			done := make(chan struct{})
			go func() {
				defer close(done)
				d.runDomains(ctx)
			}()
			defer func() {
				cancel()
				<-done
			}()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			refreshed := holdsAddress("198.51.100.7")
			for !slices.ContainsFunc(d.domainRecords(), func(r domaincache.Record) bool {
				return r.Name == name && refreshed(r)
			}) {
				select {
				case <-tick.C:
				case <-ctx.Done():
					t.Fatal("the previously observed subdomain did not refresh on schedule")
				}
			}
		})
	}
}

func TestDNSFlushRetriesStaleFileRemoval(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file removal must respect directory permissions")
	}
	dir := t.TempDir()
	d := New(Options{RuleSetDir: dir})
	d.cfg = &model.Config{}
	stale := dnsSetFile(d, "dns-obsolete")
	if err := os.WriteFile(stale, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	d.flushDomains()
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("expected the first removal to fail: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	d.flushDomains()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale file remained after the next flush: %v", err)
	}
}

// rawRule is a route rule that only describes itself.
type rawRule struct {
	adapter.Rule
	raw string
}

func (r rawRule) String() string { return r.raw }

// The routes journal names the observed names behind a DNS fallback route of
// an own list. Provider DNS sets get no note, and a route without such names
// never gets an empty one.
func TestDNSRouteNoteNamesOwnListsOnly(t *testing.T) {
	d := providerNamesDaemon(t, fullCache, nil)
	ownTag := compile.DomainTag(d.cfg.Groups[0])
	providerTag := strings.TrimSuffix(filepath.Base(dnsFileHolding(t, d, "10.0.0.0")), ".json")
	route := func(raw, ip string) string {
		t.Helper()
		d.onRoute(adapter.InboundContext{Destination: M.SocksaddrFrom(netip.MustParseAddr(ip), 443)}, rawRule{raw: raw}, nil)
		return d.Journal(journal.Routes).Find(journal.Query{}, nil).Entries[0].Rule
	}
	if got := route("rule_set=["+ownTag+"] => route(direct)", "198.51.100.1"); !strings.Contains(got, " · DNS: www.own.example") {
		t.Errorf("own list route: %q", got)
	}
	if got := route("rule_set=["+ownTag+"] => route(direct)", "198.51.100.200"); strings.Contains(got, "DNS:") {
		t.Errorf("own list route without observed names: %q", got)
	}
	if got := route("rule_set=["+providerTag+"] => route(direct)", "10.0.0.0"); strings.Contains(got, "DNS:") {
		t.Errorf("provider DNS route: %q", got)
	}
	// Explaining a provider DNS route never reads, let alone copies, the cache.
	dnsRouteNote(d.cfg, "rule_set=["+providerTag+"]", "10.0.0.0", func() []domaincache.Record {
		t.Fatal("a provider DNS route read the cache")
		return nil
	})
}

// BenchmarkDNSFlush measures the once-a-second flush with a full cache of
// 4096 names, all but one of them provider names: after one answer changed
// an address, and without a change.
func BenchmarkDNSFlush(b *testing.B) {
	b.Run("answer", func(b *testing.B) {
		d := providerNamesDaemon(b, fullCache, nil)
		answers := []*dns.Msg{
			answerA("n0.c0.example.", 300, net.IPv4(203, 0, 113, 1)),
			answerA("n0.c0.example.", 300, net.IPv4(203, 0, 113, 2)),
		}
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			d.observeDomain("n0.c0.example.", answers[i%2])
			d.flushDomains()
		}
	})
	b.Run("unchanged", func(b *testing.B) {
		d := providerNamesDaemon(b, fullCache, nil)
		b.ReportAllocs()
		for b.Loop() {
			d.flushDomains()
		}
	})
}
