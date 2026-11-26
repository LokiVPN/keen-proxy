package model

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const validYAML = `
lan:
  interface: br0
  wan: eth3
dns:
  upstreams: ["https://1.1.1.1/dns-query", "77.88.8.8"]
intercept:
  mode: tproxy
connections:
  - id: fi
    name: Finland
    type: wireguard
    wireguard:
      private_key: cHJpdmF0ZQ==
      address: ["10.13.13.2/32"]
      peer:
        endpoint: 203.0.113.10:42820
        public_key: cHVibGlj
groups:
  - name: Foreign
    target: fi
    entries: ["youtube.com", "*.googlevideo.com", "149.154.160.0/20"]
  - name: Ads
    target: block
    entries: ["ads.example.com"]
networks:
  - name: Home
    cidr: 192.168.7.0/24
    mode: split
    target: fi
clients:
  - name: Phone
    mac: 02:00:00:00:00:10
    mode: full
    target: fi
`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if c.Intercept.TCPPort == 0 || c.DNS.Listen == "" {
		t.Fatalf("defaults not populated: %+v", c.Intercept)
	}
}

func TestValidateCollectsAllErrors(t *testing.T) {
	bad := strings.NewReplacer(
		"target: fi\n    entries", "target: nope\n    entries",
		"mac: 02:00:00:00:00:10", "mac: zz",
		"mode: tproxy", "mode: magic",
	).Replace(validYAML)
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{`unknown target "nope"`, "mac:", `unknown mode "magic"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is missing %q:\n%v", want, err)
		}
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte(validYAML + "\nfoo: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "foo") {
		t.Fatalf("unknown field must be rejected, got %v", err)
	}
}

func TestParseEntry(t *testing.T) {
	cases := []struct {
		in     string
		kind   EntryKind
		domain string
		prefix string
	}{
		{"Example.COM", EntryDomain, "example.com", ""},
		{"*.example.com", EntryDomain, "example.com", ""},
		{".example.com.", EntryDomain, "example.com", ""},
		{"\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444", EntryDomain, "xn--e1afmkfd.xn--p1ai", ""},
		{"1.2.3.4", EntryPrefix, "", "1.2.3.4/32"},
		{"10.1.2.3/8", EntryPrefix, "", "10.0.0.0/8"},
		{"2001:db8::1", EntryPrefix, "", "2001:db8::1/128"},
		{"example.com # comment", EntryDomain, "example.com", ""},
	}
	for _, c := range cases {
		e, err := ParseEntry(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if e.Kind != c.kind || e.Domain != c.domain || (c.prefix != "" && e.Prefix.String() != c.prefix) {
			t.Errorf("%q: got %+v", c.in, e)
		}
	}
	for _, bad := range []string{"", "localhost", "# only comment", "http://x"} {
		if _, err := ParseEntry(bad); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestParseUpstream(t *testing.T) {
	cases := map[string]Upstream{
		"https://1.1.1.1/dns-query": {UpstreamHTTPS, "1.1.1.1", 443, "/dns-query"},
		"https://dns.google":        {UpstreamHTTPS, "dns.google", 443, "/dns-query"},
		"tls://9.9.9.9":             {UpstreamTLS, "9.9.9.9", 853, ""},
		"udp://77.88.8.8:5353":      {UpstreamUDP, "77.88.8.8", 5353, ""},
		"8.8.8.8":                   {UpstreamUDP, "8.8.8.8", 53, ""},
	}
	for in, want := range cases {
		got, err := ParseUpstream(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v, %v; expected %+v", in, got, err, want)
		}
	}
	if _, err := ParseUpstream("ftp://x"); err == nil {
		t.Error("ftp:// must fail")
	}
}

func TestCountryGroup(t *testing.T) {
	base := "lan: {interface: br0}\ndns: {upstreams: [\"1.1.1.1\"]}\ngroups:\n"
	if _, err := Parse([]byte(base + "  - {name: g, target: direct, countries: [RU, BY], except: true}\n")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"  - {name: g, target: direct, entries: [a.com], countries: [RU]}\n",
		"  - {name: g, target: direct, countries: [rus]}\n",
		"  - {name: g, target: direct, entries: [\"!geoip:ru\"]}\n",
	} {
		if _, err := Parse([]byte(base + bad)); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestFallbackChain(t *testing.T) {
	base := `
connections:
  - {id: fi, type: link, link: "socks5://203.0.113.1:1080", fallback: nl}
  - {id: nl, type: link, link: "socks5://203.0.113.2:1080", fallback: de}
  - {id: de, type: link, link: "socks5://203.0.113.3:1080"%s}
`
	cfg, err := Parse([]byte(fmt.Sprintf(base, "")))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Chain("fi"), ","); got != "fi,nl,de" {
		t.Errorf("fi chain: %s", got)
	}
	if got := strings.Join(cfg.Chain("de"), ","); got != "de" {
		t.Errorf("de chain: %s", got)
	}
	if cfg.Failover.DownAfter != 60 || cfg.Failover.UpAfter != 120 || cfg.Failover.Interval != 15 {
		t.Errorf("defaults: %+v", cfg.Failover)
	}
	cfg, err = Parse([]byte(fmt.Sprintf(base, ", fallback: direct")))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Chain("fi"), ","); got != "fi,nl,de,direct" {
		t.Errorf("with direct: %s", got)
	}
	for tail, want := range map[string]string{
		", fallback: fi":    "cycle",
		", fallback: de":    "connection itself",
		", fallback: block": "not block",
		", fallback: xx":    "unknown fallback",
	} {
		if _, err := Parse([]byte(fmt.Sprintf(base, tail))); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected %s, got %v", tail, want, err)
		}
	}
}

func TestDeprecatedTokenSettingsAreAcceptedAndIgnored(t *testing.T) {
	cfg, err := Parse([]byte("api: {token_file: /tmp/token, no_token_from: [\"192.168.7.1\", \"not-a-network\"]}\n"))
	if err != nil {
		t.Fatalf("deprecated settings must not fail validation: %v", err)
	}
	if cfg.API.Listen == "" {
		t.Error("defaults were not applied")
	}
}

func TestParseRejectsRemovedSections(t *testing.T) {
	// v0.10 recorded catalog provenance on every group added from a preset.
	preset := strings.Replace(validYAML, "    target: block\n",
		"    target: block\n    preset: {id: ads, version: \"3\", base: [ads.example.com]}\n", 1)
	if preset == validYAML {
		t.Fatal("fixture has no group to mark as a preset")
	}
	for _, tc := range []struct{ name, raw, field string }{
		{"filters", validYAML + "filters:\n  sources: []\n", "filters"},
		{"local presets", validYAML + "local_presets:\n  - id: mine\n    name: Mine\n", "local_presets"},
		{"group preset", preset, "preset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("accepted or wrong error: %v", err)
			}
		})
	}
}

func TestSubscriptionFallbackValidation(t *testing.T) {
	cases := map[string]string{
		"direct":               "",
		"block":                "",
		"fi":                   "",
		"":                     "",
		"nope":                 "unknown fallback",
		"subscription:lv:auto": "cannot be a subscription target",
		"subscription:lv:" + strings.Repeat("a", 32): "cannot be a subscription target",
	}
	for fallback, want := range cases {
		_, err := Parse([]byte(validYAML + "subscriptions:\n  - {id: lv, url: \"https://provider.example/s\", fallback: \"" + fallback + "\"}\n"))
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("fallback %q: got %v, want %q", fallback, err, want)
		}
	}
}

func TestProviderRulesValidation(t *testing.T) {
	base := validYAML + "subscriptions:\n  - {id: lv, url: \"https://provider.example/s\"}\n"
	keys := func(n, size int) string {
		quoted := make([]string, n)
		for i := range quoted {
			key := fmt.Sprintf("proxy:geosite:c%d-", i)
			quoted[i] = fmt.Sprintf("%q", key+strings.Repeat("x", max(0, size-len(key))))
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	}
	cases := map[string]struct{ rules, want string }{
		"source and unknown keys": {`{source: lv, disabled: ["proxy:geosite:youtube", "gone:entry"]}`, ""},
		"off with unknown source": {"{source: nope, off: true}", `provider_rules.source: unknown subscription "nope"`},
		"longest key":             {"{source: lv, disabled: " + keys(1, 256) + "}", ""},
		"most keys":               {"{source: lv, disabled: " + keys(1024, 0) + "}", ""},
		"unknown source":          {"{source: nope}", `provider_rules.source: unknown subscription "nope"`},
		"missing source":          {"{disabled: [a]}", `provider_rules.source: unknown subscription ""`},
		"empty key":               {`{source: lv, disabled: ["a", ""]}`, "provider_rules.disabled[1]"},
		"long key":                {"{source: lv, disabled: " + keys(1, 257) + "}", "provider_rules.disabled[0]"},
		"too many keys":           {"{source: lv, disabled: " + keys(1025, 0) + "}", "provider_rules.disabled: at most 1024 keys"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := Parse([]byte(base + "provider_rules: " + tc.rules + "\n"))
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := c.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			again, err := Parse(raw)
			if err != nil || again.ProviderRules == nil || again.ProviderRules.Source != "lv" ||
				!slices.Equal(again.ProviderRules.Disabled, c.ProviderRules.Disabled) {
				t.Fatalf("settings did not survive a save: %+v, %v", again, err)
			}
		})
	}
	if c, err := Parse([]byte(base)); err != nil || c.ProviderRules != nil {
		t.Fatalf("provider rules must default to off: %+v, %v", c.ProviderRules, err)
	}
}

func TestProviderRulesOffRoundTrip(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + `
subscriptions:
  - {id: lv, url: "https://provider.example/s"}
provider_rules: {source: lv, off: true, disabled: ["proxy:geosite:youtube"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"source":"lv","off":true,"disabled":["proxy:geosite:youtube"]}`
	for _, c := range []*Config{cfg, cfg.Clone()} {
		got, err := json.Marshal(c.ProviderRules)
		if err != nil || string(got) != want {
			t.Fatalf("JSON settings = %s, %v, want %s", got, err, want)
		}
	}
	yaml, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := json.Marshal(loaded.ProviderRules); err != nil || string(got) != want {
		t.Fatalf("settings after YAML save = %s, %v, want %s", got, err, want)
	}
	if loaded.ActiveProviderRules() != nil {
		t.Fatal("saved off settings are active")
	}
	loaded.ProviderRules.Off = false
	active := loaded.ActiveProviderRules()
	if active == nil || active.Source != "lv" || !slices.Equal(active.Disabled, []string{"proxy:geosite:youtube"}) {
		t.Fatalf("reactivated settings = %+v", active)
	}
	if got, err := json.Marshal(active); err != nil || strings.Contains(string(got), `"off"`) {
		t.Fatalf("active settings = %s, %v", got, err)
	}
}

// Provider proxy rules and the profile default go to the policy's target, so
// a split policy that uses them without one would send that traffic direct
// without saying so. Validation rejects such configurations instead.
func TestSplitPoliciesNeedATargetForProviderRules(t *testing.T) {
	const head = `
lan: {interface: br0}
connections:
  - {id: fi, type: link, link: "socks5://203.0.113.9:1080"}
subscriptions:
  - {id: lv, url: "https://provider.example/s"}
`
	const rules = "provider_rules: {source: lv}\n"
	const off = "provider_rules: {source: lv, off: true}\n"
	const network = "default profile needs a target"
	const split = "split mode needs a target while provider_rules is set"
	cases := []struct{ name, config, want string }{
		{"profile default without a target", "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: profile}\n", network},
		{"profile default on an off network without a target", "networks:\n  - {name: Guest, cidr: 192.168.8.0/24, mode: off, default: profile}\n", network},
		{"profile default with a target", "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, target: fi, default: profile}\n", ""},
		{"provider rules still need a target with a direct default", rules + "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: direct}\n", split},
		{"provider rules and a direct default with a target", rules + "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, target: fi, default: direct}\n", ""},
		{"provider rules and an off network without a target", rules + "networks:\n  - {name: Guest, cidr: 192.168.8.0/24, mode: off}\n", ""},
		{"a split network without a target and without provider rules", "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split}\n", ""},
		{"direct default needs no target when provider rules are off", off + "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: direct}\n", ""},
		{"off provider rules still need a target for the profile default", off + "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: profile}\n", network},
		{"off provider rules and a static split device outside every network", off + "clients:\n  - {name: TV, mac: \"02:00:00:00:00:31\", ip: 10.9.0.5, mode: split}\n", ""},
		{"a static split device outside every network", rules + "clients:\n  - {name: TV, mac: \"02:00:00:00:00:31\", ip: 10.9.0.5, mode: split}\n", split},
		{"a static split device in an off network without a target", rules +
			"networks:\n  - {name: Guest, cidr: 192.168.8.0/24, mode: off}\nclients:\n  - {name: TV, mac: \"02:00:00:00:00:31\", ip: 192.168.8.5, mode: split}\n", split},
		{"a static split device with its own target", rules + "clients:\n  - {name: TV, mac: \"02:00:00:00:00:31\", ip: 10.9.0.5, mode: split, target: fi}\n", ""},
		{"a static split device in a network with a target", rules +
			"networks:\n  - {name: Guest, cidr: 192.168.8.0/24, mode: full, target: fi}\nclients:\n  - {name: TV, mac: \"02:00:00:00:00:31\", ip: 192.168.8.5, mode: split}\n", ""},
		// Its address is known only at run time, so the documentation asks
		// for its own target instead.
		{"a split device known by its MAC address", rules + "clients:\n  - {name: TV, mac: \"02:00:00:00:00:31\", mode: split}\n", ""},
		{"a static split device without provider rules", "clients:\n  - {name: TV, mac: \"02:00:00:00:00:31\", ip: 10.9.0.5, mode: split}\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(head + tc.config))
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRouteHomeThroughSubscription(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Subscriptions = []subscription.Source{{ID: "prov", URL: "https://provider.example/s/x"}}
	cfg.Networks = []Network{{Name: "Old", CIDR: "10.9.0.0/16", Mode: ModeFull, Target: "fi"}}
	cfg.ProviderRules = &ProviderRulesSettings{Source: "other", Disabled: []string{"x"}}
	cfg.RouteHomeThroughSubscription("prov", netip.MustParsePrefix("192.168.7.1/24"))
	want := []Network{{Name: "Home", CIDR: "192.168.7.0/24", Mode: ModeSplit, Target: "subscription:prov:auto", Default: TargetDirect}}
	if !slices.Equal(cfg.Networks, want) {
		t.Fatalf("networks = %+v, want %+v", cfg.Networks, want)
	}
	if cfg.ProviderRules == nil || cfg.ProviderRules.Source != "prov" || len(cfg.ProviderRules.Disabled) != 0 {
		t.Fatalf("provider rules = %+v", cfg.ProviderRules)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("result is invalid: %v", err)
	}
}
