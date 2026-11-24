package compile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// dnsNamesFor builds the DNS names of providerYAML, changed by edit, with
// rules as the provider rules of its prov subscription.
func dnsNamesFor(t *testing.T, rules ProviderRules, edit func(*model.Config)) *DNSNames {
	t.Helper()
	cfg := compileConfig(t)
	if edit != nil {
		edit(cfg)
	}
	return NewDNSNames(cfg, map[string]ProviderRules{"prov": rules})
}

// Device answers are kept for own list names and for the suffix and exact
// names of enabled provider domain rules. Keyword and regex entries match only
// a readable name, and switched-off or unavailable rules match nothing.
func TestDNSNamesObserveOwnAndProviderNames(t *testing.T) {
	names := dnsNamesFor(t, testProviderRules(), nil)
	for name, want := range map[string]bool{
		"bank.example":      true, // own group
		"www.bank.example.": true,
		"direct.example":    true, // provider suffix entries
		"cdn.video.example": true,
		"v.example":         true, // provider exact entry
		"www.v.example":     false,
		"ads.example":       true,  // block rules have fallback sets too
		"stream.example":    false, // keyword entries
		"kw.example":        false,
		"off.example":       false, // switched off
		"missing.example":   false, // unavailable
		"unrelated.example": false,
	} {
		if got := names.Observed(name); got != want {
			t.Errorf("Observed(%q) = %v, want %v", name, got, want)
		}
	}
	// Only group names are the daemon's to keep fresh.
	for name, want := range map[string]bool{
		"bank.example": true, "www.bank.example": true, "direct.example": false, "v.example": false, "unrelated.example": false,
	} {
		if got := names.InGroups(name); got != want {
			t.Errorf("InGroups(%q) = %v, want %v", name, got, want)
		}
	}
	// With provider rules off only own lists count.
	own := dnsNamesFor(t, testProviderRules(), func(c *model.Config) { c.ProviderRules = nil })
	if own.Observed("direct.example") || !own.Observed("bank.example") {
		t.Error("provider names observed while provider rules are off")
	}
}

// ruleSetCIDRs returns the addresses of a DNS fallback rule-set file.
func ruleSetCIDRs(t *testing.T, raw []byte) []string {
	t.Helper()
	var set struct {
		Rules []struct {
			CIDR []string `json:"ip_cidr"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Rules) != 1 {
		t.Fatalf("rule set %s: %v", raw, err)
	}
	return set.Rules[0].CIDR
}

// Observed answers fill every set whose names they match, provider sets
// included, and the daemon writes exactly the sets Compile declares.
func TestDNSNamesFillProviderSets(t *testing.T) {
	rules := testProviderRules()
	names := dnsNamesFor(t, rules, nil)
	sets := names.RuleSets(map[string][]string{
		"www.video.example": {"203.0.113.1", "2001:db8::1"},
		"v.example":         {"203.0.113.2"},
		"www.v.example":     {"203.0.113.3"},
		"both.example":      {"203.0.113.4", "203.0.113.4"},
		"bank.example":      {"203.0.113.5"},
		"off.example":       {"203.0.113.6"},
	})
	want := map[string][]string{
		providerDNSTag("proxy:geosite:video"):  {"203.0.113.1/32", "203.0.113.2/32", "203.0.113.4/32"},
		providerDNSTag("direct:literals:site"): {"203.0.113.4/32"},
		providerDNSTag("block:geosite:ads"):    {noSource},
		DomainTag(compileConfig(t).Groups[0]):  {"203.0.113.5/32"}, // Bank
	}
	if len(sets) != len(want) { // no sets for the switched-off and keyword-only rules
		t.Errorf("DNS sets: %d, want %d", len(sets), len(want))
	}
	for tag, cidrs := range want {
		raw, ok := sets[tag+".json"]
		if !ok {
			t.Errorf("set %s is missing", tag)
			continue
		}
		if got := ruleSetCIDRs(t, raw); !slices.Equal(got, cidrs) {
			t.Errorf("set %s = %v, want %v", tag, got, cidrs)
		}
	}
	_, out := compileProvider(t, nil, &rules)
	declared := 0
	for name := range out.RuleSets {
		if strings.HasPrefix(name, "dns-") {
			declared++
			if _, ok := sets[name]; !ok {
				t.Errorf("the daemon would not write %s", name)
			}
		}
	}
	if declared != len(sets) {
		t.Errorf("Compile declares %d DNS sets, the daemon writes %d", declared, len(sets))
	}
}

// Provider block rules answer their suffix and exact names locally unless an
// own list that routes traffic holds the name.
func TestDNSNamesProviderBlocked(t *testing.T) {
	rules := testProviderRules()
	rules.Rules = append(rules.Rules,
		ProviderRule{Key: "block:literals:site", Action: "block", Kind: "site", Source: "literals",
			Full: []string{"exact.example"}, Keyword: []string{"tracker"}},
		ProviderRule{Key: "block:geosite:gone", Action: "block", Kind: "site", Source: "geosite:gone",
			Unavailable: "not in the provider's data", Suffix: []string{"gone.example"}},
	)
	withOwnLists := func(c *model.Config) {
		c.Groups = append(c.Groups,
			model.Group{Name: "Keep", Target: "fi", Entries: []string{"keep.ads.example"}},
			model.Group{Name: "Manual", Target: model.TargetBlock, Entries: []string{"manual.ads.example"}},
		)
	}
	names := dnsNamesFor(t, rules, withOwnLists)
	for name, want := range map[string]bool{
		"ads.example":          true,
		"x.ads.example":        true,
		"X.Ads.Example.":       true,
		"exact.example":        true,
		"www.exact.example":    false,
		"keep.ads.example":     false, // own list wins
		"www.keep.ads.example": false,
		"manual.ads.example":   true,  // an own block group exempts nothing
		"tracker.example":      false, // keywords match only a readable name
		"gone.example":         false, // unavailable
		"notads.example":       false,
		"video.example":        false, // proxy rule
		"bank.example":         false,
	} {
		if got := names.ProviderBlocked(name); got != want {
			t.Errorf("ProviderBlocked(%q) = %v, want %v", name, got, want)
		}
	}
	off := dnsNamesFor(t, rules, func(c *model.Config) {
		withOwnLists(c)
		c.ProviderRules.Disabled = append(c.ProviderRules.Disabled, "block:geosite:ads")
	})
	if off.ProviderBlocked("x.ads.example") || !off.ProviderBlocked("exact.example") {
		t.Error("switching a block rule off did not release only its names")
	}
}

// Lookups do not allocate, however long the provider lists are.
func TestDNSNamesLookupsDoNotAllocate(t *testing.T) {
	suffix := make([]string, 100000)
	for i := range suffix {
		suffix[i] = fmt.Sprintf("site%06d.example", i)
	}
	// Direct comes first, so a blocked name is also checked against its keywords.
	rules := ProviderRules{RouteOrder: "direct-block-proxy", Rules: []ProviderRule{
		{Key: "direct:geosite:big", Action: "direct", Kind: "site", Source: "geosite:big", Suffix: suffix, Keyword: []string{"metrika", "counter"}},
		{Key: "block:geosite:ads", Action: "block", Kind: "site", Source: "geosite:ads", Suffix: []string{"ads.example"}},
	}}
	names := dnsNamesFor(t, rules, nil)
	for _, name := range []string{"www.site000042.example.", "x.ads.example.", "bank.example", "unrelated.example."} {
		lookup := func() {
			names.Observed(name)
			names.ProviderBlocked(name)
		}
		if n := testing.AllocsPerRun(100, lookup); n != 0 {
			t.Errorf("%s: %v allocations per lookup", name, n)
		}
	}
}

// DNS answers a provider block name locally exactly when routing rejects it:
// rules RouteOrder puts before block decide first by domain, exact name or
// keyword, and own lists before all provider rules.
func TestProviderBlockedFollowsRouteOrder(t *testing.T) {
	rules := ProviderRules{Rules: []ProviderRule{
		{Key: "direct:literals:site", Action: "direct", Kind: "site", Source: "literals",
			Suffix: []string{"yandex.example"}, Keyword: []string{"metrika"}},
		{Key: "proxy:geosite:video", Action: "proxy", Kind: "site", Source: "geosite:video",
			Suffix: []string{"video.example"}, Full: []string{"clip.example"}},
		{Key: "block:geosite:ads", Action: "block", Kind: "site", Source: "geosite:ads",
			Suffix: []string{"an.yandex.example", "ads.video.example", "metrika.ads.example", "plain.ads.example", "bank.example"},
			Full:   []string{"clip.example"}},
	}}
	names := []string{"x.an.yandex.example", "metrika.ads.example", "x.ads.video.example", "clip.example", "plain.ads.example", "www.bank.example"}
	for order, want := range map[string][]string{
		"block-direct-proxy": {"clip.example", "metrika.ads.example", "plain.ads.example", "x.ads.video.example", "x.an.yandex.example"},
		"direct-block-proxy": {"clip.example", "plain.ads.example", "x.ads.video.example"},
		"proxy-block-direct": {"metrika.ads.example", "plain.ads.example", "x.an.yandex.example"},
		"direct-proxy-block": {"plain.ads.example"},
	} {
		rules.RouteOrder = order
		dns := dnsNamesFor(t, rules, nil)
		_, out := compileProvider(t, nil, &rules)
		var blocked []string
		for _, name := range names {
			got := dns.ProviderBlocked(name)
			if got {
				blocked = append(blocked, name)
			}
			if route := routeOf(t, out, "192.168.7.0/24", name); got != (route == "reject") {
				t.Errorf("%s: %s is DNS-blocked %v, routed to %s", order, name, got, route)
			}
		}
		slices.Sort(blocked)
		if !slices.Equal(blocked, want) {
			t.Errorf("%s: DNS blocks %v, want %v", order, blocked, want)
		}
	}
}

// Provider rules route only split policies. Compile resolves a device
// address as the route rules do: the client entry holding it first, then the
// first network holding it.
func TestSplitAddresses(t *testing.T) {
	rules := testProviderRules()
	edit := func(c *model.Config) {
		c.Networks = append(c.Networks, model.Network{Name: "Guest", CIDR: "192.168.8.0/24", Mode: model.ModeFull, Target: "nl"})
		c.Clients = []model.Client{
			{Name: "TV", MAC: "02:00:00:00:00:10", Mode: model.ModeFull, Target: "nl"}, // 192.168.7.104 by neighbors
			{Name: "Printer", MAC: "02:00:00:00:00:11", Mode: model.ModeOff},           // 192.168.7.105
			{Name: "Phone", MAC: "02:00:00:00:00:12", Mode: model.ModeInherit},         // 192.168.7.106
			{Name: "Laptop", MAC: "02:00:00:00:00:20", IP: "192.168.8.50", Mode: model.ModeSplit},
			{Name: "Console", MAC: "02:00:00:00:00:21", IP: "192.168.8.51", Mode: model.ModeInherit},
		}
	}
	cfg, out := compileProvider(t, edit, &rules)
	for addr, want := range map[string]bool{
		"192.168.7.200":        true, // no client entry: the split network decides
		"::ffff:192.168.7.200": true,
		"192.168.7.104":        false, // a full-tunnel client in the split network
		"192.168.7.105":        false, // off
		"192.168.7.106":        true,  // inherits split
		"192.168.8.50":         true,  // a split client in the full network
		"192.168.8.51":         false, // inherits full
		"192.168.8.200":        false,
		"10.0.0.1":             false,
	} {
		if got := out.Split.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
	// Clients sharing an address: off and full-tunnel classes route first.
	shared := splitAddresses([]policy{
		{source: netip.MustParsePrefix("192.168.7.150/32"), mode: model.ModeFull},
		{source: netip.MustParsePrefix("192.168.7.150/32"), mode: model.ModeSplit},
		{source: netip.MustParsePrefix("192.168.7.151/32"), mode: model.ModeSplit},
		{source: netip.MustParsePrefix("192.168.7.151/32"), mode: model.ModeOff},
		{source: netip.MustParsePrefix("192.168.7.152/32"), mode: model.ModeSplit},
		{source: netip.MustParsePrefix("192.168.7.152/32"), mode: model.ModeSplit},
	}, nil)
	for addr, want := range map[string]bool{"192.168.7.150": false, "192.168.7.151": false, "192.168.7.152": true} {
		if got := shared.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("shared address %s: Contains = %v, want %v", addr, got, want)
		}
	}
	// Without its neighbor address a MAC client has no entry: the network decides.
	in := Input{Config: cfg, RuleSetDir: "/var/keenproxy", ProviderRules: map[string]ProviderRules{"prov": rules}}
	unresolved, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if !unresolved.Split.Contains(netip.MustParseAddr("192.168.7.104")) {
		t.Error("an unresolved MAC client kept its full-tunnel mode")
	}
	paused := cfg.Clone()
	paused.Paused = true
	in.Config, in.Neighbors = paused, providerNeighbors
	out, err = Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Split.Contains(netip.MustParseAddr("192.168.7.200")) || out.Split.Contains(netip.MustParseAddr("192.168.8.50")) {
		t.Error("a paused router has split devices")
	}
}
