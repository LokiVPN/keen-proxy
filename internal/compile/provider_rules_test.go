package compile

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ordo-systems/keen-proxy/internal/geodata"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// realShapedProfile mirrors the lists of a real provider profile and adds one
// entry of each other form a provider may send.
func realShapedProfile() *subscription.RoutingProfile {
	return &subscription.RoutingProfile{
		Name: "RoscomVPN", GlobalProxy: true, RouteOrder: "block-direct-proxy", DomainStrategy: "IPIfNonMatch",
		GeositeURL: "https://cdn.example/geosite.dat", GeoipURL: "https://cdn.example/geoip.dat",
		DirectSites: []string{
			"domain:remotedesktop.google.com", "geosite:private", "geosite:category-ru", "geosite:custom-list",
			"full:Exact.Example", "plain-text", "keyword:kw", `regexp:^re\.example$`, "ext:custom.dat:tag",
			"geosite:category-ru",
		},
		DirectIP:   []string{"geoip:private", "geoip:direct", "203.0.113.7", "198.51.100.9/24", "not-an-ip"},
		ProxySites: []string{"geosite:youtube", "geosite:google@cn", "geosite:missing", "geosite:empty"},
		BlockSites: []string{"geosite:category-ads"},
	}
}

func realShapedData() (map[string]geodata.Sites, map[string][]netip.Prefix) {
	sites := map[string]geodata.Sites{
		"category-ru":  {Suffix: []string{"ru"}},
		"custom-list":  {Full: []string{"custom.example"}},
		"youtube":      {Suffix: []string{"youtube.com"}, Full: []string{"youtu.be"}},
		"google@cn":    {Suffix: []string{"google.cn"}},
		"empty":        {},
		"category-ads": {Suffix: []string{"ads.example"}, Keyword: []string{"adkw"}, Regex: []string{`^ad\d+$`}},
		"unreferenced": {Suffix: []string{"unreferenced.example"}},
	}
	ips := map[string][]netip.Prefix{"direct": {netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}}
	return sites, ips
}

func requireProviderRules(t *testing.T, got, want ProviderRules) {
	t.Helper()
	for i := range max(len(got.Rules), len(want.Rules)) {
		var g, w ProviderRule
		if i < len(got.Rules) {
			g = got.Rules[i]
		}
		if i < len(want.Rules) {
			w = want.Rules[i]
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("rule %d:\n got %+v\nwant %+v", i, g, w)
		}
	}
	got.Rules, want.Rules = nil, nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("profile fields:\n got %+v\nwant %+v", got, want)
	}
}

func TestBuildProviderRules(t *testing.T) {
	sites, ips := realShapedData()
	got := BuildProviderRules(realShapedProfile(), sites, ips, nil)
	site := func(key, label string, unavailable string, s geodata.Sites) ProviderRule {
		action, source, _ := strings.Cut(key, ":")
		return ProviderRule{Key: key, Action: action, Kind: "site", Source: source, Label: label, Unavailable: unavailable,
			Suffix: s.Suffix, Full: s.Full, Keyword: s.Keyword, Regex: s.Regex}
	}
	requireProviderRules(t, got, ProviderRules{
		Name: "RoscomVPN", RouteOrder: "block-direct-proxy", GlobalProxy: true,
		Rules: []ProviderRule{
			{Key: "direct:literals:site", Action: "direct", Kind: "site", Source: "literals", Label: "Other sites from the subscription",
				Suffix: []string{"remotedesktop.google.com"}, Full: []string{"exact.example"},
				Keyword: []string{"plain-text", "kw"}, Regex: []string{`^re\.example$`}},
			site("direct:geosite:category-ru", "Russian sites", "", sites["category-ru"]),
			site("direct:geosite:custom-list", "custom-list", "", sites["custom-list"]),
			{Key: "direct:geoip:direct", Action: "direct", Kind: "ip", Source: "geoip:direct", Label: "direct",
				CIDR: []string{"192.0.2.0/24", "2001:db8::/32"}},
			{Key: "direct:literals:ip", Action: "direct", Kind: "ip", Source: "literals", Label: "Other addresses from the subscription",
				CIDR: []string{"203.0.113.7/32", "198.51.100.0/24"}},
			site("proxy:geosite:youtube", "YouTube", "", sites["youtube"]),
			site("proxy:geosite:google@cn", "google@cn", "", sites["google@cn"]),
			site("proxy:geosite:missing", "missing", "not in the provider's data", geodata.Sites{}),
			site("proxy:geosite:empty", "empty", "not in the provider's data", geodata.Sites{}),
			site("block:geosite:category-ads", "Ads", "", sites["category-ads"]),
		},
		Unsupported: []string{"ext:custom.dat:tag", "not-an-ip"},
	})
}

func TestBuildProviderRulesWithoutProviderData(t *testing.T) {
	countries := func(code string) ([]netip.Prefix, bool) {
		if code == "RU" {
			return []netip.Prefix{netip.MustParsePrefix("5.3.0.0/16")}, true
		}
		return nil, false
	}
	rule := func(key, label, unavailable string, cidr ...string) ProviderRule {
		action, source, _ := strings.Cut(key, ":")
		kind := "ip"
		if strings.HasPrefix(source, "geosite:") {
			kind = "site"
		}
		return ProviderRule{Key: key, Action: action, Kind: kind, Source: source, Label: label, Unavailable: unavailable, CIDR: cidr}
	}
	lists := func(p *subscription.RoutingProfile) *subscription.RoutingProfile {
		p.RouteOrder = "block-direct-proxy"
		p.DirectSites = []string{"geosite:category-ru"}
		p.DirectIP = []string{"geoip:ru", "geoip:XX", "geoip:direct"}
		return p
	}

	// Without data files, countries come from the built-in database.
	got := BuildProviderRules(lists(&subscription.RoutingProfile{}), nil, nil, countries)
	requireProviderRules(t, got, ProviderRules{RouteOrder: "block-direct-proxy", Rules: []ProviderRule{
		rule("direct:geosite:category-ru", "Russian sites", "provider sent no geosite file"),
		rule("direct:geoip:ru", "ru", "", "5.3.0.0/16"),
		rule("direct:geoip:XX", "XX", "not in the built-in country data"),
		rule("direct:geoip:direct", "direct", "provider sent no geoip file"),
	}})

	// With data files that were not obtained, built-in countries are not used.
	got = BuildProviderRules(lists(&subscription.RoutingProfile{
		GeositeURL: "https://cdn.example/geosite.dat", GeoipURL: "https://cdn.example/geoip.dat",
	}), nil, nil, countries)
	requireProviderRules(t, got, ProviderRules{RouteOrder: "block-direct-proxy", Rules: []ProviderRule{
		rule("direct:geosite:category-ru", "Russian sites", "provider data not loaded"),
		rule("direct:geoip:ru", "ru", "provider data not loaded"),
		rule("direct:geoip:XX", "XX", "provider data not loaded"),
		rule("direct:geoip:direct", "direct", "provider data not loaded"),
	}})
}

func TestBuildProviderRulesBoundsUnsupportedEntries(t *testing.T) {
	long := "ext:" + strings.Repeat("a", 123) + "\u00e9" // the 128-byte cut falls inside the last rune
	p := &subscription.RoutingProfile{
		RouteOrder: "block-direct-proxy",
		ProxySites: []string{"geoip:ru", "regexp:(", "domain:", "geosite:", "geosite:@cn", "dotless:x", long, "ext:dup", "ext:dup"},
		ProxyIP:    []string{"geosite:youtube", "domain:x.example", "geoip:!cn", "geoip:", "fe80::1%eth0", "plain"},
	}
	for i := range 60 {
		p.BlockSites = append(p.BlockSites, fmt.Sprintf("ext:file.dat:tag%d", i))
	}
	got := BuildProviderRules(p, map[string]geodata.Sites{}, map[string][]netip.Prefix{}, nil)
	if len(got.Rules) != 0 {
		t.Fatalf("unsupported entries produced rules: %+v", got.Rules)
	}
	want := []string{
		"geoip:ru", "regexp:(", "domain:", "geosite:", "geosite:@cn", "dotless:x", long[:127], "ext:dup",
		"geosite:youtube", "domain:x.example", "geoip:!cn", "geoip:", "fe80::1%eth0", "plain",
	}
	if len(got.Unsupported) != 50 || !reflect.DeepEqual(got.Unsupported[:len(want)], want) {
		t.Fatalf("unsupported = %d %q", len(got.Unsupported), got.Unsupported)
	}
	for _, entry := range got.Unsupported {
		if len(entry) > 128 || !utf8.ValidString(entry) {
			t.Fatalf("unbounded unsupported entry %q", entry)
		}
	}
}

func TestProviderRuleRefs(t *testing.T) {
	sites, ips := ProviderRuleRefs(realShapedProfile())
	wantSites := map[string]bool{"category-ru": true, "custom-list": true, "youtube": true, "google@cn": true, "missing": true, "empty": true, "category-ads": true}
	if !reflect.DeepEqual(sites, wantSites) || !reflect.DeepEqual(ips, map[string]bool{"direct": true}) {
		t.Fatalf("refs = %v %v", sites, ips)
	}
}
