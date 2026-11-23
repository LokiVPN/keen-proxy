package compile

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

const defaultHead = `
lan: {interface: br0, wan: eth3}
dns: {upstreams: ["https://1.1.1.1/dns-query"]}
intercept: {mode: tproxy}
connections:
  - id: fi
    type: wireguard
    wireguard:
      private_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
      address: ["10.13.13.2/32"]
      mtu: 1408
      peer:
        endpoint: 203.0.113.10:42820
        public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
        keepalive: 25
groups:
  - {name: Bank, target: direct, entries: ["bank.ru"]}
`

func compileDefault(t *testing.T, tail string) Output {
	t.Helper()
	cfg, err := model.Parse([]byte(defaultHead + tail))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Compile(Input{Config: cfg, RuleSetDir: "/var/keenproxy", Neighbors: map[string]netip.Addr{
		"02:00:00:00:00:10": netip.MustParseAddr("192.168.7.104"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// routeLines renders non-sniff route rules as "sources sets → outbound".
func routeLines(t *testing.T, out Output) []string {
	t.Helper()
	var cfg struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.SingBox, &cfg); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range cfg.Route.Rules {
		dst, _ := r["outbound"].(string)
		if dst == "" {
			continue
		}
		sets := joinField(r["rule_set"])
		if sub, ok := r["rules"].([]any); ok {
			var parts []string
			for _, x := range sub {
				m := x.(map[string]any)
				parts = append(parts, joinField(m["rule_set"])+joinField(m["source_ip_cidr"]))
			}
			sets = strings.Join(parts, "&")
		}
		got = append(got, joinField(r["source_ip_cidr"])+" "+sets+" → "+dst)
	}
	return got
}

func hasLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	at := -1
	for _, w := range want {
		found := false
		for i := at + 1; i < len(got); i++ {
			if got[i] == w {
				at, found = i, true
				break
			}
		}
		if !found {
			t.Fatalf("missing %q in order:\n%s", w, strings.Join(got, "\n"))
		}
	}
}

func TestSplitNetworkDefaultUsesTarget(t *testing.T) {
	out := compileDefault(t, "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: fi}\n")
	got := routeLines(t, out)
	hasLines(t, got, "192.168.7.0/24 group-0 → direct", "192.168.7.0/24  → fi")
	if strings.Contains(strings.Join(got, "\n"), "192.168.7.0/24  → direct") {
		t.Errorf("direct final rule remains:\n%s", strings.Join(got, "\n"))
	}
}

func TestSplitClientsInheritNetworkDefault(t *testing.T) {
	out := compileDefault(t, `networks:
  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: fi}
clients:
  - {name: Phone, mac: "02:00:00:00:00:10"}
`)
	hasLines(t, routeLines(t, out), " clients-split-to-fi&group-0 → direct", " clients-split-to-fi → fi")
	if !strings.Contains(string(out.RuleSets["clients-split-to-fi.json"]), "192.168.7.104/32") {
		t.Errorf("client missing from class:\n%s", out.RuleSets["clients-split-to-fi.json"])
	}
	if strings.Contains(string(out.RuleSets["clients-split.json"]), "192.168.7.104/32") {
		t.Error("client also in the direct split class")
	}
}

func TestDifferentDefaultsDoNotMerge(t *testing.T) {
	out := compileDefault(t, `networks:
  - {name: A, cidr: 192.168.7.0/24, mode: split, default: fi}
  - {name: B, cidr: 192.168.8.0/24, mode: split}
  - {name: C, cidr: 192.168.9.0/24, mode: split}
`)
	got := routeLines(t, out)
	hasLines(t, got, "192.168.7.0/24  → fi", "192.168.8.0/24,192.168.9.0/24  → direct")
}

func TestProfileDefaultCompilesAsDirect(t *testing.T) {
	out := compileDefault(t, "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: profile}\n")
	hasLines(t, routeLines(t, out), "192.168.7.0/24  → direct")
}

func TestDefaultRejectsBlock(t *testing.T) {
	_, err := model.Parse([]byte(defaultHead + "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: block}\n"))
	if err == nil || !strings.Contains(err.Error(), "default cannot be block") {
		t.Fatalf("err = %v", err)
	}
	_, err = model.Parse([]byte(defaultHead + "networks:\n  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: nowhere}\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown target") {
		t.Fatalf("err = %v", err)
	}
}

func TestSingBoxAcceptsSplitDefault(t *testing.T) {
	out := compileDefault(t, `networks:
  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: fi}
clients:
  - {name: Phone, mac: "02:00:00:00:00:10"}
`)
	dir := t.TempDir()
	for name, raw := range out.RuleSets {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := []byte(strings.ReplaceAll(string(out.SingBox), "/var/keenproxy/", dir+"/"))
	ctx := engine.Context(context.Background())
	opts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out.SingBox)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("sing-box rejected configuration: %v\n%s", err, out.SingBox)
	}
	instance.Close()
}
