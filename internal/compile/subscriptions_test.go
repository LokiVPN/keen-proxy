package compile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const subscriptionConfig = `
subscriptions:
  - id: provider
    url: https://provider.example/sub/example-token
    send_hwid: true
groups:
  - {name: Video, target: "subscription:provider:auto", entries: ["video.example"]}
networks:
  - {name: Home, cidr: 192.0.2.0/24, mode: split}
  - {name: Office, cidr: 198.51.100.0/24, mode: full, target: "subscription:provider:auto"}
clients:
  - {name: Phone, mac: "02:00:00:00:00:10", ip: "192.0.2.2", mode: full, target: "subscription:provider:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
`

func TestUnavailableSubscriptionTargetsCompileToBlock(t *testing.T) {
	cfg, err := model.Parse([]byte(subscriptionConfig))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Compile(Input{Config: cfg, RuleSetDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Outbounds []struct {
			Tag  string
			Type string
		}
		Route struct{ Rules []struct{ Outbound string } }
	}
	if err := json.Unmarshal(out.SingBox, &got); err != nil {
		t.Fatal(err)
	}
	blocks, blockedRules := 0, 0
	for _, outbound := range got.Outbounds {
		if outbound.Type == "block" && outbound.Tag == model.TargetBlock {
			blocks++
		}
	}
	for _, rule := range got.Route.Rules {
		if rule.Outbound == model.TargetBlock {
			blockedRules++
		}
	}
	if blocks != 1 || blockedRules < 3 {
		t.Fatalf("pending group, network, and device must block, got %d block outbounds and %d rules", blocks, blockedRules)
	}
	var clientClass bool
	for name, content := range out.RuleSets {
		if strings.HasPrefix(name, classFull) && strings.Contains(string(content), "192.0.2.2/32") {
			clientClass = true
		}
	}
	if !clientClass {
		t.Fatal("the pinned device was omitted from the compiled client classes")
	}
}

func TestSubscriptionOrderChangesPriorityWithoutChangingEngine(t *testing.T) {
	cfg, err := model.Parse([]byte(subscriptionConfig))
	if err != nil {
		t.Fatal(err)
	}
	first := subscription.Node{ID: strings.Repeat("a", 32), Name: "First", Link: "socks5://203.0.113.2:1080"}
	second := subscription.Node{ID: strings.Repeat("b", 32), Name: "Second", Link: "socks5://203.0.113.3:1080"}
	in := Input{Config: cfg, RuleSetDir: t.TempDir(), Subscriptions: map[string][]subscription.Node{"provider": {first, second}}}
	before, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	first.Name = "Renamed"
	in.Subscriptions["provider"] = []subscription.Node{second, first}
	after, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.SingBox, before.SingBox) {
		t.Fatal("display name or preference change restarted the engine")
	}
	fixed := model.ManagedTarget("provider", first.ID)
	ordered := []string{model.ManagedTarget("provider", second.ID), fixed}
	if len(after.SubscriptionSelectors) != 1 || !slices.Equal(after.SubscriptionSelectors[0].Candidates, ordered) {
		t.Fatalf("provider order was lost: %+v", after.SubscriptionSelectors)
	}
	if !slices.Contains(after.SubscriptionOutbounds, fixed) {
		t.Fatal("pinned outbound is missing")
	}
	if slices.Contains(after.Plan.Bypass, netip.MustParsePrefix("203.0.113.2/32")) {
		t.Fatal("a provider node added a destination firewall bypass")
	}
}

func TestSubscriptionIDCannotAliasManualConnection(t *testing.T) {
	cfg, err := model.Parse([]byte(subscriptionConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Connections = []model.Connection{{ID: "subscription:provider:auto", Type: model.ConnLink, Link: "socks5://203.0.113.2:1080"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "conflicts with a subscription") {
		t.Fatalf("ambiguous target accepted: %v", err)
	}
}

func TestMixedSubscriptionCatalogCompilesFullProfileSet(t *testing.T) {
	cfg, err := model.Parse([]byte(subscriptionConfig))
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]subscription.Node, 0, 47)
	for i := range 47 {
		link := fmt.Sprintf("vless://11111111-2222-3333-4444-555555555555@vpn.example:%d?type=tcp", 4000+i)
		switch {
		case i < 3:
			extra := url.QueryEscape(`{"sessionIDTable":"hex","sessionIDLength":"16-32"}`)
			link = fmt.Sprintf("vless://11111111-2222-3333-4444-555555555555@vpn.example:%d?type=xhttp&mode=packet-up&extra=%s", 4000+i, extra)
		case i >= 42:
			link = fmt.Sprintf("hysteria2://example-password@vpn.example:%d", 4000+i)
		}
		nodes = append(nodes, subscription.Node{ID: fmt.Sprintf("%032x", i+1), Link: link})
	}
	out, err := Compile(Input{Config: cfg, RuleSetDir: t.TempDir(), Subscriptions: map[string][]subscription.Node{"provider": nodes}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.SubscriptionSelectors) != 1 || len(out.SubscriptionOutbounds) != len(nodes) {
		t.Fatalf("managed nodes compiled: %d, want %d", len(out.SubscriptionOutbounds), len(nodes))
	}
}

func TestSubscriptionBalancePoliciesShareConcreteNodes(t *testing.T) {
	cfg, err := model.Parse([]byte(`
subscriptions:
  - {id: provider, url: "https://provider.example/sub/list"}
groups:
  - {name: Site, target: "subscription:provider:consistent-hash", entries: ["site.example"]}
  - {name: Old automatic, target: "subscription:provider:auto", entries: ["auto.example"]}
networks:
  - {name: Home, cidr: 192.0.2.0/24, mode: full, target: "subscription:provider:round-robin"}
clients:
  - {name: Phone, mac: "02:00:00:00:00:10", ip: "192.0.2.2", mode: full, target: "subscription:provider:sticky-session"}
  - {name: Laptop, mac: "02:00:00:00:00:11", ip: "192.0.2.3", mode: full, target: "subscription:provider:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
`))
	if err != nil {
		t.Fatal(err)
	}
	first := subscription.Node{ID: strings.Repeat("a", 32), Link: "socks5://203.0.113.2:1080"}
	second := subscription.Node{ID: strings.Repeat("b", 32), Link: "socks5://203.0.113.3:1080"}
	input := Input{Config: cfg, RuleSetDir: t.TempDir()}
	empty, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.SubscriptionBalances) != 3 || len(empty.SubscriptionOutbounds) != 0 {
		t.Fatalf("empty catalog lost pending balance targets: %+v", empty.SubscriptionBalances)
	}
	for _, balance := range empty.SubscriptionBalances {
		if len(balance.Candidates) != 0 {
			t.Fatalf("empty catalog yielded candidates for %s", balance.Tag)
		}
	}
	input.Subscriptions = map[string][]subscription.Node{"provider": {second, first}}
	compiled, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []string{"consistent-hash", "round-robin", "sticky-session"}
	members := []string{model.ManagedTarget("provider", first.ID), model.ManagedTarget("provider", second.ID)}
	if len(compiled.SubscriptionBalances) != len(fixtures) || !slices.Equal(compiled.SubscriptionOutbounds, members) {
		t.Fatalf("compiled %d balances with members %v", len(compiled.SubscriptionBalances), compiled.SubscriptionOutbounds)
	}
	for i, balance := range compiled.SubscriptionBalances {
		strategy := fixtures[i]
		if balance.SourceID != "provider" || balance.Strategy != strategy ||
			balance.Tag != model.ManagedTarget("provider", strategy) ||
			!slices.Equal(balance.Candidates, members) {
			t.Fatalf("incorrect %s policy: %+v", strategy, balance)
		}
	}
	if len(compiled.SubscriptionSelectors) != 1 ||
		!slices.Equal(compiled.SubscriptionSelectors[0].Candidates, []string{members[1], members[0]}) {
		t.Fatalf("automatic selector lost its provider priority: %+v", compiled.SubscriptionSelectors)
	}
}

func TestSubscriptionSelectorIncludesFallback(t *testing.T) {
	cfg, err := model.Parse([]byte(subscriptionConfig + `
connections:
  - {id: home, type: link, link: "socks5://203.0.113.9:1080", fallback: direct}
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Subscriptions[0].Fallback = "home"
	node := subscription.Node{ID: strings.Repeat("a", 32), Name: "First", Link: "socks5://203.0.113.2:1080"}
	out, err := Compile(Input{Config: cfg, RuleSetDir: t.TempDir(), Subscriptions: map[string][]subscription.Node{"provider": {node}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.SubscriptionSelectors) != 1 || out.SubscriptionSelectors[0].Fallback != FailoverTagPrefix+"home" {
		t.Fatalf("reserve did not resolve through the failover chain: %+v", out.SubscriptionSelectors)
	}
	var got struct {
		Outbounds []struct {
			Tag       string
			Outbounds []string
		}
	}
	if err := json.Unmarshal(out.SingBox, &got); err != nil {
		t.Fatal(err)
	}
	for _, o := range got.Outbounds {
		if o.Tag == "subscription:provider:auto" && slices.Contains(o.Outbounds, FailoverTagPrefix+"home") {
			return
		}
	}
	t.Fatal("selector does not offer the reserve")
}

func TestSubscriptionWithoutNodesCompilesToFallback(t *testing.T) {
	cfg, err := model.Parse([]byte(subscriptionConfig + `
connections:
  - {id: home, type: link, link: "socks5://203.0.113.9:1080"}
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Subscriptions[0].Fallback = "home"
	out, err := Compile(Input{Config: cfg, RuleSetDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var got struct{ Route struct{ Rules []struct{ Outbound string } } }
	if err := json.Unmarshal(out.SingBox, &got); err != nil {
		t.Fatal(err)
	}
	reserve := 0
	for _, r := range got.Route.Rules {
		switch r.Outbound {
		case model.TargetBlock:
			t.Fatalf("a rule still blocks: %+v", got.Route.Rules)
		case "home":
			reserve++
		}
	}
	if reserve < 3 {
		t.Fatalf("group, network and pinned device must use the reserve, got %d rules", reserve)
	}
}
