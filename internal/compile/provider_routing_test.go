package compile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	sjson "github.com/sagernet/sing/common/json"

	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

const providerYAML = `
lan: {interface: br0}
dns: {upstreams: ["https://1.1.1.1/dns-query"]}
connections:
  - {id: fi, type: link, link: "socks5://203.0.113.9:1080"}
  - {id: nl, type: link, link: "socks5://203.0.113.10:1080"}
subscriptions:
  - {id: prov, url: "https://provider.example/sub/example-token"}
provider_rules: {source: prov, disabled: ["direct:geosite:off"]}
groups:
  - {name: Bank, target: direct, entries: ["bank.example"]}
  - {name: Except Russia, target: fi, countries: [RU], except: true}
networks:
  - {name: Home, cidr: 192.168.7.0/24, mode: split, target: fi, default: profile}
`

// testProviderRules holds one rule of each kind and action, in profile order,
// plus a switched-off and an unavailable rule. both.example is in a direct
// and a proxy list.
func testProviderRules() ProviderRules {
	return ProviderRules{
		Name: "Test", RouteOrder: "block-direct-proxy", GlobalProxy: true,
		Rules: []ProviderRule{
			{Key: "direct:literals:site", Action: "direct", Kind: "site", Source: "literals",
				Suffix: []string{"both.example", "direct.example"}, Keyword: []string{"kw"}},
			{Key: "direct:geosite:off", Action: "direct", Kind: "site", Source: "geosite:off", Suffix: []string{"off.example"}},
			{Key: "direct:geoip:direct", Action: "direct", Kind: "ip", Source: "geoip:direct", CIDR: []string{"192.0.2.0/24"}},
			{Key: "proxy:geosite:video", Action: "proxy", Kind: "site", Source: "geosite:video",
				Suffix: []string{"both.example", "video.example"}, Full: []string{"v.example"}},
			{Key: "proxy:geosite:words", Action: "proxy", Kind: "site", Source: "geosite:words", Keyword: []string{"stream"}},
			{Key: "proxy:geosite:missing", Action: "proxy", Kind: "site", Source: "geosite:missing", Unavailable: "not in the provider's data",
				Suffix: []string{"missing.example"}},
			{Key: "proxy:literals:ip", Action: "proxy", Kind: "ip", Source: "literals", CIDR: []string{"198.51.100.0/24"}},
			{Key: "block:geosite:ads", Action: "block", Kind: "site", Source: "geosite:ads", Suffix: []string{"ads.example"}},
		},
	}
}

var providerNeighbors = map[string]netip.Addr{
	"02:00:00:00:00:10": netip.MustParseAddr("192.168.7.104"),
	"02:00:00:00:00:11": netip.MustParseAddr("192.168.7.105"),
	"02:00:00:00:00:12": netip.MustParseAddr("192.168.7.106"),
}

// compileProvider compiles providerYAML after edit with rules as the
// provider rules of the prov subscription (none when nil).
func compileProvider(t *testing.T, edit func(*model.Config), rules *ProviderRules) (*model.Config, Output) {
	t.Helper()
	cfg, err := model.Parse([]byte(providerYAML))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(cfg)
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	in := Input{Config: cfg, RuleSetDir: "/var/keenproxy", Neighbors: providerNeighbors}
	if rules != nil {
		in.ProviderRules = map[string]ProviderRules{"prov": *rules}
	}
	out, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, out
}

// routeRule is one compiled route rule: the source or client class it
// applies to, the rule sets it matches ("!" marks an inverted match) and
// where it sends traffic.
type routeRule struct {
	who  string
	sets []string
	dns  bool // matches only connections without a domain
	to   string
}

func routeRules(t *testing.T, out Output) []routeRule {
	t.Helper()
	var cfg struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.SingBox, &cfg); err != nil {
		t.Fatal(err)
	}
	var rules []routeRule
	for _, r := range cfg.Route.Rules {
		var got routeRule
		var read func(part map[string]any)
		read = func(part map[string]any) {
			if sub, ok := part["rules"].([]any); ok { // logical AND, possibly nested
				for _, x := range sub {
					read(x.(map[string]any))
				}
				return
			}
			if src := joinField(part["source_ip_cidr"]); src != "" {
				got.who = src
			}
			if _, ok := part["domain_regex"]; ok {
				got.dns = true
			}
			list, _ := part["rule_set"].([]any)
			for _, v := range list {
				switch tag := v.(string); {
				case strings.HasPrefix(tag, "clients-"):
					got.who = tag
				case part["invert"] == true:
					got.sets = append(got.sets, "!"+tag)
				default:
					got.sets = append(got.sets, tag)
				}
			}
		}
		read(r)
		got.to, _ = r["outbound"].(string)
		if got.to == "" {
			got.to, _ = r["action"].(string)
		}
		rules = append(rules, got)
	}
	return rules
}

// chain renders the route rules of one source or client class as
// "<sets> → <outbound or action>", naming provider sets by rule key and DNS
// fallback sets of config groups by group name.
func chain(t *testing.T, cfg *model.Config, rules ProviderRules, out Output, who string) []string {
	t.Helper()
	names := map[string]string{}
	for _, r := range rules.Rules {
		names[providerRuleTag(r.Key)] = r.Key
		names[providerDNSTag(r.Key)] = r.Key
	}
	for _, g := range cfg.Groups {
		names[DomainTag(g)] = g.Name
	}
	var lines []string
	for _, r := range routeRules(t, out) {
		if r.who != who {
			continue
		}
		var sets []string
		for _, tag := range r.sets {
			plain, invert := strings.CutPrefix(tag, "!")
			if name, ok := names[plain]; ok {
				tag = name
				if invert {
					tag = "!" + name
				}
			}
			sets = append(sets, tag)
		}
		line := strings.Join(sets, "&")
		if r.dns {
			line = "dns " + line
		}
		lines = append(lines, line+" → "+r.to)
	}
	return lines
}

func requireLines(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n%s\nwant:\n%s", what, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// routeOf follows the rules of who and returns where a connection to domain
// goes: the first rule whose rule set sing-box's own matcher puts the domain
// in, or the policy's final rule. DNS fallback rules never match a
// connection with a domain, and countries never match by name.
func routeOf(t *testing.T, out Output, who, domain string) string {
	t.Helper()
	ctx := engine.Context(context.Background())
	var cfg struct {
		Route struct {
			RuleSet []json.RawMessage `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.SingBox, &cfg); err != nil {
		t.Fatal(err)
	}
	sets := map[string][]byte{}
	for _, raw := range cfg.Route.RuleSet {
		var set struct {
			Tag, Type string
			Rules     json.RawMessage
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			t.Fatal(err)
		}
		sets[set.Tag] = out.RuleSets[set.Tag+".json"]
		if set.Type == "inline" {
			sets[set.Tag] = fmt.Appendf(nil, `{"version": 3, "rules": %s}`, set.Rules)
		}
	}
	contains := func(tag string) bool {
		file, err := sjson.UnmarshalExtendedContext[option.PlainRuleSetCompat](ctx, sets[tag])
		if err != nil {
			return false // a country placeholder the daemon fills
		}
		plain, err := file.Upgrade()
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range plain.Rules {
			headless, err := rule.NewHeadlessRule(ctx, options)
			if err != nil {
				t.Fatalf("rule set %s: %v", tag, err)
			}
			if headless.Match(&adapter.InboundContext{Domain: domain}) {
				return true
			}
		}
		return false
	}
	for _, r := range routeRules(t, out) {
		if r.who != who || r.dns || slices.ContainsFunc(r.sets, func(tag string) bool { return strings.HasPrefix(tag, "!") }) {
			continue
		}
		if len(r.sets) == 0 || slices.ContainsFunc(r.sets, contains) {
			return r.to
		}
	}
	t.Fatalf("no rule of %s routes %s", who, domain)
	return ""
}

// wantChain is the chain of a split policy for testProviderRules in the
// default RouteOrder whose provider proxy rules and profile default go to
// target.
func wantChain(target string) []string { return wantRoute(target, target) }

// wantRoute is wantChain with provider proxy rules to proxy and unmatched
// traffic to fallback.
func wantRoute(proxy, fallback string) []string {
	target := proxy
	return []string{
		"group-0 → direct",
		"dns Bank → direct",
		"block:geosite:ads → reject",
		"direct:literals:site → direct",
		"proxy:geosite:video → " + target,
		"proxy:geosite:words → " + target,
		"dns block:geosite:ads → reject",
		"dns direct:literals:site → direct",
		"dns proxy:geosite:video → " + target,
		"direct:geoip:direct → direct",
		"proxy:literals:ip → " + target,
		"!geoip-ru → fi",
		" → " + fallback,
	}
}

// Own groups first, then provider domain rules in RouteOrder, DNS fallback
// for them, provider IP rules in RouteOrder, country groups, the default.
func TestProviderRuleOrder(t *testing.T) {
	rules := testProviderRules()
	cfg, out := compileProvider(t, nil, &rules)
	requireLines(t, "block-direct-proxy", chain(t, cfg, rules, out, "192.168.7.0/24"), wantChain("fi"))

	rules.RouteOrder = "direct-proxy-block"
	cfg, out = compileProvider(t, nil, &rules)
	requireLines(t, "direct-proxy-block", chain(t, cfg, rules, out, "192.168.7.0/24"), []string{
		"group-0 → direct",
		"dns Bank → direct",
		"direct:literals:site → direct",
		"proxy:geosite:video → fi",
		"proxy:geosite:words → fi",
		"block:geosite:ads → reject",
		"dns direct:literals:site → direct",
		"dns proxy:geosite:video → fi",
		"dns block:geosite:ads → reject",
		"direct:geoip:direct → direct",
		"proxy:literals:ip → fi",
		"!geoip-ru → fi",
		" → fi",
	})

	// Provider blocks stay in the policies; the global block section, which
	// applies to every source, has none.
	for _, line := range chain(t, cfg, rules, out, "") {
		if strings.Contains(line, ":") {
			t.Errorf("provider rule outside the split policies: %s", line)
		}
	}
	// Switched-off and unavailable rules leave no rule set behind.
	for _, key := range []string{"direct:geosite:off", "proxy:geosite:missing"} {
		if _, ok := out.RuleSets[providerRuleTag(key)+".json"]; ok || strings.Contains(string(out.SingBox), providerRuleTag(key)) {
			t.Errorf("rule %s was compiled", key)
		}
	}
}

// Large lists live in one local file per rule, shared by every policy, and
// the DNS fallback sets start as non-matching placeholders.
func TestProviderRuleSets(t *testing.T) {
	rules := testProviderRules()
	_, out := compileProvider(t, func(c *model.Config) {
		c.Networks = append(c.Networks, model.Network{Name: "Lab", CIDR: "192.168.8.0/24", Mode: model.ModeSplit, Target: "nl"})
	}, &rules)
	want := map[string]string{
		"direct:literals:site": `{"rules":[{"domain_keyword":["kw"],"domain_suffix":["both.example","direct.example"]}],"version":3}`,
		"direct:geoip:direct":  `{"rules":[{"ip_cidr":["192.0.2.0/24"]}],"version":3}`,
		"proxy:geosite:video":  `{"rules":[{"domain":["v.example"],"domain_suffix":["both.example","video.example"]}],"version":3}`,
		"proxy:geosite:words":  `{"rules":[{"domain_keyword":["stream"]}],"version":3}`,
		"proxy:literals:ip":    `{"rules":[{"ip_cidr":["198.51.100.0/24"]}],"version":3}`,
		"block:geosite:ads":    `{"rules":[{"domain_suffix":["ads.example"]}],"version":3}`,
	}
	for key, file := range want {
		tag := providerRuleTag(key)
		if got := string(out.RuleSets[tag+".json"]); got != file {
			t.Errorf("%s file:\n got %s\nwant %s", key, got, file)
		}
		if n := strings.Count(string(out.SingBox), `"tag": "`+tag+`"`); n != 1 {
			t.Errorf("%s is declared %d times", key, n)
		}
	}
	placeholder := `{"rules":[{"ip_cidr":["255.255.255.255/32"]}],"version":3}`
	for _, key := range []string{"direct:literals:site", "proxy:geosite:video", "block:geosite:ads"} {
		if got := string(out.RuleSets[providerDNSTag(key)+".json"]); got != placeholder {
			t.Errorf("%s DNS fallback set = %s", key, got)
		}
	}
	if _, ok := out.RuleSets[providerDNSTag("proxy:geosite:words")+".json"]; ok {
		t.Error("a keyword-only rule got a DNS fallback set")
	}
	dns := NewDNSNames(compileConfig(t), map[string]ProviderRules{"prov": rules}).RuleSets(nil)
	for name, raw := range out.RuleSets {
		if strings.HasPrefix(name, "dns-") && string(dns[name]) != string(raw) {
			t.Errorf("the daemon would not keep %s", name)
		}
	}
	if len(dns) != 4 { // Bank and three provider site rules
		t.Errorf("DNS sets: %d", len(dns))
	}

	// The same input compiles to the same bytes.
	_, again := compileProvider(t, func(c *model.Config) {
		c.Networks = append(c.Networks, model.Network{Name: "Lab", CIDR: "192.168.8.0/24", Mode: model.ModeSplit, Target: "nl"})
	}, &rules)
	if !reflect.DeepEqual(out, again) {
		t.Error("compilation is not deterministic")
	}
}

func compileConfig(t *testing.T) *model.Config {
	t.Helper()
	cfg, err := model.Parse([]byte(providerYAML))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Proxy rules and the profile default follow each policy's own target;
// split networks with different targets keep separate rules.
func TestProviderProxyRulesUseThePolicyTarget(t *testing.T) {
	rules := testProviderRules()
	cfg, out := compileProvider(t, func(c *model.Config) {
		c.Networks = append(c.Networks, model.Network{Name: "Lab", CIDR: "192.168.8.0/24", Mode: model.ModeSplit, Target: "nl", Default: model.DefaultProfile})
	}, &rules)
	requireLines(t, "Lab", chain(t, cfg, rules, out, "192.168.8.0/24"), wantChain("nl"))
	requireLines(t, "Home", chain(t, cfg, rules, out, "192.168.7.0/24"), wantChain("fi"))

	// The same direct default does not merge networks whose targets differ.
	cfg, out = compileProvider(t, func(c *model.Config) {
		c.Networks[0].Default = ""
		c.Networks = append(c.Networks, model.Network{Name: "Lab", CIDR: "192.168.8.0/24", Mode: model.ModeSplit, Target: "nl"})
	}, &rules)
	requireLines(t, "Lab with a direct default", chain(t, cfg, rules, out, "192.168.8.0/24"), wantRoute("nl", "direct"))
	requireLines(t, "Home with a direct default", chain(t, cfg, rules, out, "192.168.7.0/24"), wantRoute("fi", "direct"))
}

func TestProfileDefaultFollowsTheProviderProfile(t *testing.T) {
	direct := testProviderRules()
	direct.GlobalProxy = false
	for _, tc := range []struct {
		name  string
		rules *ProviderRules
		off   bool
		want  string
	}{
		{"global proxy", new(testProviderRules()), false, "fi"},
		{"global direct", &direct, false, "direct"},
		{"no provider rules yet", nil, false, "fi"},
		{"provider rules off", new(testProviderRules()), true, "fi"},
	} {
		cfg, out := compileProvider(t, func(c *model.Config) {
			if tc.off {
				c.ProviderRules = nil
			}
		}, tc.rules)
		lines := chain(t, cfg, testProviderRules(), out, "192.168.7.0/24")
		if got := lines[len(lines)-1]; got != " → "+tc.want {
			t.Errorf("%s: default %q", tc.name, got)
		}
		if tc.rules == nil || tc.off {
			requireLines(t, tc.name, lines, []string{"group-0 → direct", "dns Bank → direct", "!geoip-ru → fi", " → fi"})
		}
	}
}

// Split clients get the same rules as split networks, through their own
// target; off devices and a paused router get none.
func TestSplitClientClassesReceiveProviderRules(t *testing.T) {
	rules := testProviderRules()
	devices := func(c *model.Config) {
		c.Clients = []model.Client{
			{Name: "Phone", MAC: "02:00:00:00:00:10"},
			{Name: "Tablet", MAC: "02:00:00:00:00:11", Mode: model.ModeSplit, Target: "nl"},
			{Name: "Laptop", MAC: "02:00:00:00:00:12", Mode: model.ModeOff},
		}
	}
	cfg, out := compileProvider(t, devices, &rules)
	classOf := func(ip string) string {
		t.Helper()
		var found []string
		for name, raw := range out.RuleSets {
			if strings.HasPrefix(name, "clients-") && strings.Contains(string(raw), `"`+ip+`/32"`) {
				found = append(found, strings.TrimSuffix(name, ".json"))
			}
		}
		if len(found) != 1 {
			t.Fatalf("%s is in classes %v", ip, found)
		}
		return found[0]
	}
	requireLines(t, "Phone", chain(t, cfg, rules, out, classOf("192.168.7.104")), wantChain("fi"))
	requireLines(t, "Tablet", chain(t, cfg, rules, out, classOf("192.168.7.105")), wantChain("nl"))
	requireLines(t, "Laptop", chain(t, cfg, rules, out, classOf("192.168.7.106")), []string{" → direct"})

	// With a direct default the two split devices still need their own classes.
	cfg, out = compileProvider(t, func(c *model.Config) {
		devices(c)
		c.Networks[0].Default = ""
	}, &rules)
	requireLines(t, "Phone with a direct default", chain(t, cfg, rules, out, classOf("192.168.7.104")), wantRoute("fi", "direct"))
	requireLines(t, "Tablet with a direct default", chain(t, cfg, rules, out, classOf("192.168.7.105")), wantRoute("nl", "direct"))

	// Classes depend on configuration, not on current addresses.
	in := Input{Config: cfg, RuleSetDir: "/var/keenproxy", ProviderRules: map[string]ProviderRules{"prov": rules}}
	absent, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(absent.SingBox) != string(out.SingBox) {
		t.Error("client addresses changed the sing-box configuration")
	}

	cfg, out = compileProvider(t, func(c *model.Config) {
		devices(c)
		c.Paused = true
	}, &rules)
	requireLines(t, "paused network", chain(t, cfg, rules, out, "192.168.7.0/24"), []string{" → direct"})
	if len(out.Plan.Sources) != 0 {
		t.Errorf("paused plan intercepts %v", out.Plan.Sources)
	}
}

// A domain in a direct and a proxy list follows the list RouteOrder puts first.
func TestProviderRouteOrderDecidesSharedDomains(t *testing.T) {
	for order, want := range map[string]string{
		"block-direct-proxy": "direct",
		"block-proxy-direct": "fi",
		"proxy-direct-block": "fi",
		"direct-proxy-block": "direct",
	} {
		rules := testProviderRules()
		rules.RouteOrder = order
		_, out := compileProvider(t, nil, &rules)
		if got := routeOf(t, out, "192.168.7.0/24", "www.both.example"); got != want {
			t.Errorf("%s: www.both.example goes to %s, want %s", order, got, want)
		}
	}
	rules := testProviderRules()
	_, out := compileProvider(t, nil, &rules)
	for domain, want := range map[string]string{
		"bank.example": "direct", "ads.example": "reject", "video.example": "fi", "live.stream.example": "fi",
		"off.example": "fi", // switched off: the default applies
	} {
		if got := routeOf(t, out, "192.168.7.0/24", domain); got != want {
			t.Errorf("%s goes to %s, want %s", domain, got, want)
		}
	}
}

// Geosite entries sing-box would reject, or that would match every name, are
// dropped and counted; the rules keep the rest, a rule left empty is skipped
// and the daemon's data is not modified.
func TestProviderRulesDropUnusableEntries(t *testing.T) {
	rules := ProviderRules{RouteOrder: "block-direct-proxy", GlobalProxy: true, Rules: []ProviderRule{
		{Key: "proxy:geosite:mixed", Action: "proxy", Kind: "site", Source: "geosite:mixed",
			Suffix: []string{"", "mixed.example"}, Keyword: []string{""}, Regex: []string{"(", `^re\.example$`, ""}},
		{Key: "proxy:geosite:broken", Action: "proxy", Kind: "site", Source: "geosite:broken", Regex: []string{"[z-a]"}},
	}}
	before := cloneRules(rules)
	cfg, out := compileProvider(t, nil, &rules)
	if !reflect.DeepEqual(rules, before) {
		t.Fatal("compilation modified the provider rules")
	}
	if out.DroppedProviderEntries != 5 {
		t.Errorf("dropped %d entries, want 5", out.DroppedProviderEntries)
	}
	if got := string(out.RuleSets[providerRuleTag("proxy:geosite:mixed")+".json"]); got != `{"rules":[{"domain_regex":["^re\\.example$"],"domain_suffix":["mixed.example"]}],"version":3}` {
		t.Errorf("mixed rule file: %s", got)
	}
	requireLines(t, "rules", chain(t, cfg, rules, out, "192.168.7.0/24"), []string{
		"group-0 → direct",
		"dns Bank → direct",
		"proxy:geosite:mixed → fi",
		"dns proxy:geosite:mixed → fi",
		"!geoip-ru → fi",
		" → fi",
	})
	requireSingBoxAccepts(t, out)
}

func cloneRules(r ProviderRules) ProviderRules {
	raw, _ := json.Marshal(r)
	var c ProviderRules
	_ = json.Unmarshal(raw, &c)
	return c
}

// requireSingBoxAccepts writes the rule sets the daemon would write and
// validates the configuration through the engine's validation path.
func requireSingBoxAccepts(t *testing.T, out Output) {
	t.Helper()
	dir := t.TempDir()
	for name, raw := range out.RuleSets {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, code := range out.Countries {
		if err := os.WriteFile(filepath.Join(dir, CountryTagPrefix+strings.ToLower(code)+".json"), CountryRuleSet(nil), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := strings.ReplaceAll(string(out.SingBox), "/var/keenproxy/", dir+"/")
	if err := engine.Validate(t.Context(), []byte(config)); err != nil {
		t.Fatalf("sing-box rejected the configuration: %v", err)
	}
}

// The real-shaped profile with extracted data, including a provider-size
// address list and an invalid regex, compiles to a configuration sing-box
// accepts.
func TestSingBoxAcceptsProviderRules(t *testing.T) {
	sites, ips := realShapedData()
	ads := sites["category-ads"]
	ads.Regex = append(slices.Clone(ads.Regex), "(")
	sites["category-ads"] = ads
	large := make([]netip.Prefix, 0, 35000)
	for i := range 35000 {
		large = append(large, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24))
	}
	ips["direct"] = append(ips["direct"], large...)
	rules := BuildProviderRules(realShapedProfile(), sites, ips, nil)
	_, out := compileProvider(t, func(c *model.Config) {
		c.Clients = []model.Client{{Name: "Phone", MAC: "02:00:00:00:00:10"}, {Name: "Tablet", MAC: "02:00:00:00:00:11", Mode: model.ModeSplit, Target: "nl"}}
	}, &rules)
	if out.DroppedProviderEntries != 1 {
		t.Errorf("dropped %d entries, want the invalid regex", out.DroppedProviderEntries)
	}
	requireSingBoxAccepts(t, out)
}
