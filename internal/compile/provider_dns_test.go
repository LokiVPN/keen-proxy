package compile

import (
	"encoding/json"
	"fmt"
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
	rules := ProviderRules{RouteOrder: "block-direct-proxy", Rules: []ProviderRule{
		{Key: "direct:geosite:big", Action: "direct", Kind: "site", Source: "geosite:big", Suffix: suffix},
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
