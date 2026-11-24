package daemon

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/dnsfront"
	"github.com/ordo-systems/keen-proxy/internal/domaincache"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// dnsUpstream answers every A query with ip over UDP and returns its address
// as a DNS upstream setting.
func dnsUpstream(t *testing.T, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if q := r.Question[0]; q.Qtype == dns.TypeA {
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}}
			}
			_ = w.WriteMsg(m)
		})}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return "udp://" + pc.LocalAddr().String()
}

// dnsServer returns the DNS frontend d runs.
func dnsServer(d *Daemon) *dnsfront.Server {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dns
}

// lanDevice is a device of the split network withLAN adds, as host:port.
const lanDevice = "192.168.77.10:5353"

// withLAN adds the split network the DNS tests query from. Provider rules
// need its target.
func withLAN(cfg *model.Config) {
	cfg.Networks = append(cfg.Networks, model.Network{Name: "LAN", CIDR: "192.168.77.0/24", Mode: model.ModeSplit, Target: "subscription:sample:auto"})
}

// resolveA asks srv for the A record of name as the device at client
// (host:port) would, and returns the first address or the response code.
func resolveA(t *testing.T, srv *dnsfront.Server, client, name string) string {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r := srv.Resolve(dnsfront.WithClient(t.Context(), client), q)
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return dns.RcodeToString[r.Rcode]
}

// dnsAnswer is a successful answer a device received.
func dnsAnswer(t *testing.T, records ...string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	for _, record := range records {
		rr, err := dns.NewRR(record)
		if err != nil {
			t.Fatal(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	return m
}

// dnsFilesWith lists the DNS fallback rule-set files of d that hold text.
func dnsFilesWith(t *testing.T, d *Daemon, text string) []string {
	t.Helper()
	var found []string
	for _, name := range ruleSetFiles(t, d, "dns-") {
		raw, err := os.ReadFile(filepath.Join(d.opt.RuleSetDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), text) {
			found = append(found, name)
		}
	}
	return found
}

func observedNames(d *Daemon) []string {
	var names []string
	for _, r := range d.domainRecords() {
		names = append(names, r.Name)
	}
	return names
}

// Answers to device queries for provider domains fill the rule's DNS fallback
// set. The daemon never resolves those names itself, and the names of a
// switched-off rule are not kept.
func TestProviderDomainsFillDNSFallbackFromDeviceAnswersOnly(t *testing.T) {
	d, cfg, _ := newRulesTestDaemon(t)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	d.observeDomain("www.direct.example.", dnsAnswer(t, "www.direct.example. 60 IN A 203.0.113.7"))
	d.observeDomain("x.ads.example.", dnsAnswer(t, "x.ads.example. 60 IN A 203.0.113.8")) // switched off
	d.flushDomains()

	own := compile.DomainTag(cfg.Groups[0]) + ".json" // the Video group
	if got := dnsFilesWith(t, d, `"203.0.113.7/32"`); len(got) != 1 || got[0] == own {
		t.Fatalf("provider answer reached DNS sets %v (own set %s)", got, own)
	}
	if got := dnsFilesWith(t, d, "203.0.113.8"); len(got) != 0 || slices.Contains(observedNames(d), "x.ads.example") {
		t.Fatalf("a switched-off rule's answer was kept: %v", got)
	}
	// Only own names stay warm: configured roots and recently observed own
	// subdomains. Provider names cannot be resolved by the daemon at all.
	names := refreshDomainNames(d.live.Load(), d.domainRecords(), time.Now())
	if containsName(names, "www.direct.example") || !containsName(names, "video.example") {
		t.Fatalf("names kept warm: %v", names)
	}
	if err := d.RefreshDomains(t.Context(), []string{"www.direct.example"}); err == nil {
		t.Fatal("the daemon accepted a provider name for its own resolution")
	}
}

// Enabled provider block rules are answered locally unless an own list that
// routes traffic holds the name; config block groups keep blocking. The
// routes journal names the kind of rule behind each local answer.
func TestProviderBlockRulesAnswerDNSLocally(t *testing.T) {
	d, cfg, _ := newRulesTestDaemon(t)
	cfg.DNS.Upstreams = []string{dnsUpstream(t, "198.51.100.7")}
	cfg.ProviderRules.Disabled = nil
	withLAN(cfg)
	cfg.Groups = append(cfg.Groups,
		model.Group{Name: "Keep", Target: model.TargetDirect, Entries: []string{"keep.ads.example"}},
		model.Group{Name: "Manual", Target: model.TargetBlock, Entries: []string{"manual.example", "manual.ads.example"}},
	)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	srv := dnsServer(d)
	for name, want := range map[string]string{
		"x.ads.example":        "0.0.0.0",
		"keep.ads.example":     "198.51.100.7",
		"www.keep.ads.example": "198.51.100.7",
		"www.manual.example":   "0.0.0.0",
		"x.manual.ads.example": "0.0.0.0",
		"other.example":        "198.51.100.7",
	} {
		if got := resolveA(t, srv, lanDevice, name); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	for source, want := range map[string][]string{
		"provider": {"x.ads.example."},
		"manual":   {"www.manual.example.", "x.manual.ads.example."},
	} {
		var hosts []string
		for _, e := range d.Journal(journal.Routes).Find(journal.Query{Filters: map[string]string{"source": source}}, nil).Entries {
			hosts = append(hosts, e.Host)
		}
		slices.Sort(hosts)
		if !slices.Equal(hosts, want) {
			t.Errorf("%s blocks journaled for %v, want %v", source, hosts, want)
		}
	}
}

// The running DNS frontend and the observation follow provider rule changes
// from Apply and from a subscription refresh.
func TestProviderDNSFollowsRuleChanges(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	cfg.DNS.Upstreams = []string{dnsUpstream(t, "198.51.100.7")}
	withLAN(cfg)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	srv := dnsServer(d)
	if got := resolveA(t, srv, lanDevice, "x.ads.example"); got != "198.51.100.7" {
		t.Fatalf("a switched-off block rule answered %s", got)
	}

	on := cfg.Clone()
	on.ProviderRules.Disabled = nil
	if err := d.Apply(t.Context(), on); err != nil {
		t.Fatal(err)
	}
	if got := resolveA(t, srv, lanDevice, "x.ads.example"); got != "0.0.0.0" {
		t.Fatalf("a switched-on block rule answered %s", got)
	}

	if got := resolveA(t, srv, lanDevice, "x.tracker.example"); got != "198.51.100.7" {
		t.Fatalf("tracker.example answered %s before the provider listed it", got)
	}
	d.observeDomain("www.unused.example.", dnsAnswer(t, "www.unused.example. 60 IN A 203.0.113.9"))
	if slices.Contains(observedNames(d), "www.unused.example") {
		t.Fatal("a name outside every list was kept")
	}
	// The provider adds a domain to its block category and a new category.
	runSubscriptionTestWorker(t, d)
	p.update(func(p *rulesProvider) {
		p.files["/v2/geosite.dat"] = testGeosite(map[string][]string{
			"VIDEO": {"video.example"}, "ADS": {"ads.example", "tracker.example"}, "UNUSED": {"unused.example"},
		})
	})
	p.useProfile("/v2/geosite.dat", "/geoip.dat", "geosite:unused")
	refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.State == subscription.StateReady })
	if got := resolveA(t, srv, lanDevice, "x.tracker.example"); got != "0.0.0.0" {
		t.Fatalf("a refreshed block rule answered %s", got)
	}
	d.observeDomain("www.unused.example.", dnsAnswer(t, "www.unused.example. 60 IN A 203.0.113.9"))
	if !slices.Contains(observedNames(d), "www.unused.example") {
		t.Fatal("a refreshed provider rule's name was not kept")
	}
}

// The DNS names are built when the configuration or the provider rules
// change, never per answer: an answer costs no allocation and a recompile
// with the same inputs keeps the names.
func TestProviderDNSNamesBuiltOncePerChange(t *testing.T) {
	d, cfg, _ := newRulesTestDaemon(t)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	built := d.dnsNames.Load()
	answer := dnsAnswer(t, "www.unrelated.example. 60 IN A 203.0.113.10")
	if n := testing.AllocsPerRun(100, func() { d.observeDomain("www.unrelated.example.", answer) }); n != 0 {
		t.Errorf("an unrelated answer cost %v allocations", n)
	}
	d.flushDomains()
	d.mu.Lock()
	_, err := d.compileLocked()
	d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if built == nil || d.dnsNames.Load() != built {
		t.Fatal("the DNS names were rebuilt without a change")
	}
}

// Nothing refreshes a provider name, so its record leaves the DNS cache once
// its answer expires and does not weigh on every flush. Group names stay for
// their refresh, also when a provider rule lists them too.
func TestExpiredProviderAnswersLeaveTheCache(t *testing.T) {
	d, cfg, _ := newRulesTestDaemon(t)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	d.domains = domaincache.New(func() time.Time { return now })
	d.observeDomain("www.direct.example.", dnsAnswer(t, "www.direct.example. 5 IN A 203.0.113.7"))
	d.observeDomain("cdn.direct.example.", dnsAnswer(t, "cdn.direct.example. 60 IN A 203.0.113.8"))
	d.observeDomain("www.video.example.", dnsAnswer(t, "www.video.example. 5 IN A 203.0.113.9")) // the Video group
	now = now.Add(10 * time.Second)
	d.flushDomains()
	if got := observedNames(d); !slices.Equal(got, []string{"cdn.direct.example", "www.video.example"}) {
		t.Fatalf("cached names %v", got)
	}
}

// DNS goroutines keep reading the names while Apply replaces them.
func TestProviderDNSNamesSwapDuringLookups(t *testing.T) {
	d, cfg, _ := newRulesTestDaemon(t)
	cfg.DNS.Upstreams = []string{dnsUpstream(t, "198.51.100.7")}
	withLAN(cfg)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	srv := dnsServer(d)
	answer := dnsAnswer(t, "x.ads.example. 60 IN A 203.0.113.11")
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				d.observeDomain("x.ads.example.", answer)
				if got := resolveA(t, srv, lanDevice, "x.ads.example"); got != "0.0.0.0" && got != "198.51.100.7" {
					t.Errorf("x.ads.example = %s", got)
				}
				_ = d.domainRecords()
			}
		}()
	}
	for i := range 10 {
		next := cfg.Clone()
		if i%2 == 0 {
			next.ProviderRules.Disabled = nil
		}
		if err := d.Apply(t.Context(), next); err != nil {
			t.Error(err)
		}
	}
	close(done)
	wg.Wait()
}

// Provider rules route only split policies, so only their devices get local
// answers for provider block names: a full-tunnel device in the same network
// gets the real answer, while block groups block every device. A client known
// only by its MAC counts once a recompilation learns its address.
func TestProviderBlocksOnlyForSplitDevices(t *testing.T) {
	d, cfg, _ := newRulesTestDaemon(t)
	cfg.DNS.Upstreams = []string{dnsUpstream(t, "198.51.100.7")}
	cfg.ProviderRules.Disabled = nil
	withLAN(cfg)
	cfg.Groups = append(cfg.Groups, model.Group{Name: "Manual", Target: model.TargetBlock, Entries: []string{"manual.example"}})
	cfg.Clients = []model.Client{
		{Name: "TV", MAC: "02:00:00:00:00:31", IP: "192.168.77.31", Mode: model.ModeFull, Target: "subscription:sample:auto"},
		{Name: "Console", MAC: "02:00:00:00:00:32", Mode: model.ModeFull, Target: "subscription:sample:auto"},
	}
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	srv := dnsServer(d)
	for _, q := range []struct{ client, name, want string }{
		{lanDevice, "x.ads.example", "0.0.0.0"},
		{"192.168.77.31:5353", "x.ads.example", "198.51.100.7"},
		{lanDevice, "www.manual.example", "0.0.0.0"},
		{"192.168.77.31:5353", "www.manual.example", "0.0.0.0"},
		{"192.168.77.32:5353", "x.ads.example", "0.0.0.0"}, // Console's address is not known yet
	} {
		if got := resolveA(t, srv, q.client, q.name); got != q.want {
			t.Errorf("%s from %s = %s, want %s", q.name, q.client, got, q.want)
		}
	}
	arp := "IP address HW type Flags HW address Mask Device\n192.168.77.32 0x1 0x2 02:00:00:00:00:32 * br0\n"
	if err := os.WriteFile(d.opt.ARPPath, []byte(arp), 0o600); err != nil {
		t.Fatal(err)
	}
	d.watch(t.Context())
	if got := resolveA(t, srv, "192.168.77.32:5353", "x.ads.example"); got != "198.51.100.7" {
		t.Errorf("x.ads.example from Console after its address was learned = %s, want the real answer", got)
	}
}
