package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

const balanceTestSource = "provider"

func TestSubscriptionBalanceRoundRobinTracksConcreteMember(t *testing.T) {
	route := newSubscriptionBalanceTest(t, "round-robin", nil)
	if _, err := route.get("video.example"); err == nil {
		t.Fatal("an unchecked subscription allowed a new connection")
	}
	route.update("source-a", route.tags[1], route.tags[0], route.tags[0], "direct")
	for _, want := range []string{"first", "second", "first", "second"} {
		route.expect("video.example", want)
	}

	for _, want := range []string{"block", route.tags[0], route.tags[1], route.tags[0], route.tags[1]} {
		var got subscriptionBalanceTestRoute
		select {
		case got = <-route.routed:
		default:
			t.Fatal("the tracker missed a routed connection")
		}
		if got.rule == "" {
			t.Fatal("the matched rule was missing from the tracker")
		}
		if got.tag != want {
			t.Fatalf("the tracker counted traffic against %q, want %q", got.tag, want)
		}
	}
	counts := make(map[string]stats.Outbound)
	for _, value := range route.tracker.Snapshot(false).Outbounds {
		counts[value.Tag] = value
	}
	for _, tag := range route.tags {
		if count := counts[tag]; count.UpTotal == 0 || count.DownTotal == 0 {
			t.Fatalf("node %q has no accounted traffic: %+v", tag, count)
		}
	}
	route.update("source-a")
	if _, err := route.get("video.example"); err == nil {
		t.Fatal("an empty eligible set allowed a new connection")
	}
}

func TestSubscriptionBalanceSiteMappingIsStableAcrossProviderReorder(t *testing.T) {
	route := newSubscriptionBalanceTest(t, "consistent-hash", nil)
	third := subscriptionTestNode(t, strings.Repeat("c", 32), "third")
	route.nodes = append(route.nodes, third)
	route.tags = append(route.tags, model.ManagedTarget(balanceTestSource, third.ID))
	route.apply(nil)
	route.update("source-a", route.tags...)
	sites := make(map[string]string)
	members := make(map[string]bool)
	for i := range 24 {
		site := fmt.Sprintf("site%d.example", i)
		marker, err := route.get("www." + site)
		if err != nil {
			t.Fatal(err)
		}
		route.expect("static."+site, marker)
		sites[site], members[marker] = marker, true
	}
	if len(members) != 3 {
		t.Fatalf("site mappings used %d different nodes, want 3", len(members))
	}

	before := route.plan()
	slices.Reverse(route.nodes)
	orderOnly := route.plan()
	if !bytes.Equal(before.SingBox, orderOnly.SingBox) {
		t.Fatal("provider order changed the compiled runtime")
	}
	route.update("source-a", route.tags[2], route.tags[1], route.tags[0])
	for site, marker := range sites {
		route.expect(site, marker)
	}

	route.update("source-a", route.tags[0], route.tags[2])
	for site, marker := range sites {
		if marker == "second" {
			got, err := route.get(site)
			if err != nil || (got != "first" && got != "third") {
				t.Fatalf("site %q assigned to removed member routed to %q (%v)", site, got, err)
			}
			continue
		}
		route.expect(site, marker)
	}
	route.update("source-a", route.tags...)
	for site, marker := range sites {
		route.expect(site, marker)
	}
}

func TestSubscriptionBalanceStickyAssignmentsSurviveSameSourceRestart(t *testing.T) {
	route := newSubscriptionBalanceTest(t, "sticky-session", nil)
	route.update("source-a", route.tags[0])
	for i := range 48 {
		route.expect(fmt.Sprintf("app.site%d.example", i), "first")
	}

	route.apply(func(raw map[string]any) {
		raw["log"].(map[string]any)["level"] = "error"
	})
	route.update("source-a", route.tags...)
	for i := range 48 {
		route.expect(fmt.Sprintf("img.site%d.example", i), "first")
	}

	route.update("source-b", route.tags...)
	remapped := 0
	for i := range 48 {
		got, err := route.get(fmt.Sprintf("img.site%d.example", i))
		if err != nil {
			t.Fatal(err)
		}
		if got == "second" {
			remapped++
		}
	}
	if remapped == 0 {
		t.Fatal("the replacement source kept all the old source's assignments")
	}
	route.update("source-b", route.tags[1])
	route.expect("app.site0.example", "second")
	route.update("source-b", route.tags...)
	route.expect("img.site0.example", "second")
}

func TestSubscriptionBalanceBlocksUnsupportedTransport(t *testing.T) {
	route := newSubscriptionBalanceTest(t, "round-robin", nil)
	route.apply(func(raw map[string]any) {
		for _, value := range raw["outbounds"].([]any) {
			out := value.(map[string]any)
			switch out["tag"] {
			case route.tags[0]:
				out["network"] = "tcp"
			case route.tags[1]:
				out["network"] = "udp"
			}
		}
	})
	route.update("source-a", route.tags[0])
	route.expect("video.example", "first")
	out, ctx, ok := route.engine.Outbound(route.tag)
	if !ok {
		t.Fatal("compiled subscription balance was missing")
	}
	conn, err := out.ListenPacket(ctx, M.ParseSocksaddr("203.0.113.70:80"))
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("incompatible UDP member must use the block outbound, got %v", err)
	}
	route.update("source-a", route.tags[1])
	tcp, err := out.DialContext(ctx, "tcp", M.ParseSocksaddr("203.0.113.70:80"))
	if tcp != nil {
		_ = tcp.Close()
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("UDP-only pool must block TCP, got %v", err)
	}
}

type subscriptionBalanceTest struct {
	t       *testing.T
	cfg     *model.Config
	dir     string
	nodes   []subscription.Node
	tag     string
	tags    []string
	tracker *stats.Tracker
	routed  chan subscriptionBalanceTestRoute
	port    int
	client  *http.Client
	engine  Engine
}

type subscriptionBalanceTestRoute struct {
	tag  string
	rule string
}

func newSubscriptionBalanceTest(t *testing.T, strategy string, onRoute func(string)) *subscriptionBalanceTest {
	t.Helper()
	tag := model.ManagedTarget(balanceTestSource, strategy)
	cfg := &model.Config{
		Subscriptions: []subscription.Source{{ID: balanceTestSource, URL: "https://provider.example/sub/list"}},
		Groups:        []model.Group{{Name: "Balance", Target: tag, Entries: []string{"203.0.113.70"}}},
		Networks:      []model.Network{{Name: "Client", CIDR: "127.0.0.1/32", Mode: model.ModeSplit}},
	}
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate configured subscription balance: %v", err)
	}

	first := subscriptionTestNode(t, strings.Repeat("a", 32), "first")
	second := subscriptionTestNode(t, strings.Repeat("b", 32), "second")
	listener := subscriptionTestListener(t)
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	tracker := stats.NewTracker()
	route := &subscriptionBalanceTest{
		t: t, cfg: cfg, dir: t.TempDir(), nodes: []subscription.Node{first, second}, tag: tag,
		tags:    []string{model.ManagedTarget(balanceTestSource, first.ID), model.ManagedTarget(balanceTestSource, second.ID)},
		tracker: tracker, routed: make(chan subscriptionBalanceTestRoute, 256), port: port,
		client: &http.Client{Transport: transport, Timeout: 3 * time.Second}, engine: Engine{Tracker: tracker},
	}
	tracker.OnRoute = func(_ adapter.InboundContext, rule adapter.Rule, out adapter.Outbound) {
		var description string
		if rule != nil {
			description = rule.String()
		}
		route.routed <- subscriptionBalanceTestRoute{tag: out.Tag(), rule: description}
		if onRoute != nil {
			onRoute(out.Tag())
		}
	}
	t.Cleanup(func() {
		route.drainTrackedRoutes()
		_ = route.engine.Close()
	})
	route.apply(nil)
	return route
}

func (r *subscriptionBalanceTest) plan() compile.Output {
	r.t.Helper()
	plan, err := compile.Compile(compile.Input{
		Config: r.cfg, RuleSetDir: r.dir, Subscriptions: map[string][]subscription.Node{balanceTestSource: r.nodes},
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return plan
}

func (r *subscriptionBalanceTest) apply(adjust func(map[string]any)) {
	r.t.Helper()
	r.drainTrackedRoutes()
	plan := r.plan()
	for name, contents := range plan.RuleSets {
		path := filepath.Join(r.dir, name)
		if previous, _ := os.ReadFile(path); bytes.Equal(previous, contents) {
			continue
		}
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			r.t.Fatal(err)
		}
	}
	var runtime map[string]any
	if err := json.Unmarshal(plan.SingBox, &runtime); err != nil {
		r.t.Fatal(err)
	}
	// Keep the compiled routing and replace router-only interception with a portable ingress.
	runtime["inbounds"] = []any{
		map[string]any{"type": "direct", "tag": "tcp-in", "listen": "127.0.0.1", "listen_port": r.port,
			"network": "tcp", "override_address": "203.0.113.70", "override_port": 80},
	}
	if adjust != nil {
		adjust(runtime)
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		r.t.Fatal(err)
	}
	if restarted, err := r.engine.Apply(raw); err != nil || !restarted {
		r.t.Fatalf("start compiled subscription balance: restarted=%v err=%v", restarted, err)
	}
}

// Completed loopback requests pass through the tracker before dial. Receiving
// those events synchronizes route matching with the engine restart or cleanup.
func (r *subscriptionBalanceTest) drainTrackedRoutes() {
	for {
		select {
		case <-r.routed:
		default:
			return
		}
	}
}

func (r *subscriptionBalanceTest) update(key string, tags ...string) {
	r.t.Helper()
	if !r.engine.UpdateSubscriptionBalance(r.tag, key, tags) {
		r.t.Fatal("could not update the compiled subscription balance")
	}
}

func (r *subscriptionBalanceTest) get(site string) (string, error) {
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", r.port), nil)
	if err != nil {
		return "", err
	}
	request.Host = site
	response, err := r.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	return string(body), err
}

func (r *subscriptionBalanceTest) expect(site, want string) {
	r.t.Helper()
	got, err := r.get(site)
	if err != nil || got != want {
		r.t.Fatalf("route for %q carried %q (%v), want %q", site, got, err, want)
	}
}

func TestSubscriptionBalanceConcurrentUpdateKeepsTrackedChoice(t *testing.T) {
	tracked := make(chan string, 1)
	resume := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(resume) })
	var first sync.Once
	route := newSubscriptionBalanceTest(t, "round-robin", func(member string) {
		first.Do(func() {
			tracked <- member
			<-resume
		})
	})
	route.update("source-a", route.tags[0])

	type reply struct {
		body string
		err  error
	}
	replies := make(chan reply, 1)
	go func() {
		body, err := route.get("video.example")
		replies <- reply{body, err}
	}()
	select {
	case member := <-tracked:
		if member != route.tags[0] {
			t.Fatalf("tracked node %q, want %q", member, route.tags[0])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("connection did not reach the tracker")
	}

	route.update("source-a", route.tags[1])
	release.Do(func() { close(resume) })
	result := <-replies
	if result.err != nil || result.body != "first" {
		t.Fatalf("in-flight connection returned %q (%v), want first", result.body, result.err)
	}
	route.expect("video.example", "second")
}

func TestSubscriptionBalanceKeepsStickyPrimaryAcrossUDPTransportFallback(t *testing.T) {
	route := newSubscriptionBalanceTest(t, "sticky-session", nil)
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	port := echo.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buffer := make([]byte, 16)
		n, client, err := echo.ReadFromUDP(buffer)
		if err == nil {
			_, _ = echo.WriteToUDP(buffer[:n], client)
		}
	}()

	route.apply(func(raw map[string]any) {
		inbounds := raw["inbounds"].([]any)
		raw["inbounds"] = append(inbounds, map[string]any{
			"type": "direct", "tag": "udp-in", "listen": "127.0.0.1", "listen_port": route.port,
			"network": "udp", "override_address": "203.0.113.70", "override_port": 80,
		})
		for i, item := range raw["outbounds"].([]any) {
			out := item.(map[string]any)
			switch out["tag"] {
			case route.tags[0]:
				out["network"] = "tcp"
			case route.tags[1]:
				raw["outbounds"].([]any)[i] = map[string]any{"type": "direct", "tag": route.tags[1]}
			}
		}
		for _, item := range raw["route"].(map[string]any)["rules"].([]any) {
			rule := item.(map[string]any)
			if rule["outbound"] == route.tag {
				rule["override_address"], rule["override_port"] = "127.0.0.1", port
			}
		}
	})
	route.update("source-a", route.tags[0])
	route.expect("127.0.0.1", "first")
	if got := <-route.routed; got.tag != route.tags[0] {
		t.Fatalf("recorded TCP route %+v, want %q", got, route.tags[0])
	}

	route.update("source-a", route.tags...)
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: route.port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("keenproxy")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, err := conn.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("routed UDP response %q (%v), want %q", buffer[:n], err, payload)
	}
	got := <-route.routed
	if got.tag != route.tags[1] || got.rule == "" {
		t.Fatalf("recorded UDP route %+v, want compatible member %q", got, route.tags[1])
	}
	route.expect("127.0.0.1", "first")
	for _, counts := range route.tracker.Snapshot(false).Outbounds {
		if counts.Tag == route.tags[1] && counts.DownTotal > 0 && counts.UpTotal > 0 {
			return
		}
	}
	t.Fatal("UDP traffic was not accounted to the compatible member")
}

func TestSubscriptionBalanceStickySessionExpiresAfterThirtyMinutesIdle(t *testing.T) {
	route := newSubscriptionBalanceTest(t, "sticky-session", nil)
	members := subscriptionBalanceTestMembers(t, route)
	var sessions subscriptionBalanceSessions
	start := time.Unix(1, 0)
	client := netip.MustParseAddr("192.0.2.2")
	other := netip.MustParseAddr("192.0.2.3")
	key := subscriptionBalanceSessionKey{client: client, site: "example.com"}
	otherDevice := subscriptionBalanceSessionKey{client: other, site: key.site}
	last := func(n int) int { return n - 1 }
	sessions.selectAt(key, members[:1], nil, start, last)
	if tag := sessions.selectAt(otherDevice, members, nil, start, last).Tag(); tag != route.tags[1] {
		t.Fatalf("other device received %q, want a new session", tag)
	}
	for _, d := range []time.Duration{29 * time.Minute, 58 * time.Minute} {
		if tag := sessions.selectAt(key, members, nil, start.Add(d), last).Tag(); tag != route.tags[0] {
			t.Fatalf("active session moved to %q at %v", tag, d)
		}
	}
	if tag := sessions.selectAt(key, members, nil, start.Add(88*time.Minute), last).Tag(); tag != route.tags[1] {
		t.Fatalf("expired session kept member %q", tag)
	}
}

func TestSubscriptionBalanceStickySessionEvictsLeastRecentlyUsedAtCapacity(t *testing.T) {
	route := newSubscriptionBalanceTest(t, "sticky-session", nil)
	members := subscriptionBalanceTestMembers(t, route)
	var sessions subscriptionBalanceSessions
	now := time.Unix(1, 0)
	client := netip.MustParseAddr("192.0.2.2")
	key := func(i int) subscriptionBalanceSessionKey {
		return subscriptionBalanceSessionKey{client: client, site: fmt.Sprintf("site%d.example", i)}
	}
	last := func(n int) int { return n - 1 }
	for i := range 1024 {
		sessions.selectAt(key(i), members[:1], nil, now, last)
	}
	sessions.selectAt(key(0), members[:1], nil, now, last)
	sessions.selectAt(key(1024), members[:1], nil, now, last)
	if tag := sessions.selectAt(key(0), members, nil, now, last).Tag(); tag != route.tags[0] {
		t.Fatalf("recent session moved to %q after filling the cache", tag)
	}
	if tag := sessions.selectAt(key(1), members, nil, now, last).Tag(); tag != route.tags[1] {
		t.Fatalf("least recently used session kept member %q after bounded eviction", tag)
	}
}

func subscriptionBalanceTestMembers(t *testing.T, route *subscriptionBalanceTest) []subscriptionBalanceMember {
	t.Helper()
	var members []subscriptionBalanceMember
	for i, tag := range route.tags {
		member, _, ok := route.engine.Outbound(tag)
		if !ok {
			t.Fatalf("compiled member %q was missing", tag)
		}
		members = append(members, subscriptionBalanceMember{outbound: member, order: i})
	}
	return members
}

func TestSubscriptionBalanceCheckpointPreservesAssignmentsAcrossRollback(t *testing.T) {
	tests := []struct {
		name      string
		apply     func(*subscriptionBalanceTest)
		reconcile func(*subscriptionBalanceTest)
	}{
		{
			name: "removed policy",
			apply: func(route *subscriptionBalanceTest) {
				target := route.cfg.Groups[0].Target
				route.cfg.Groups[0].Target = model.TargetDirect
				route.apply(nil)
				route.cfg.Groups[0].Target = target
			},
			reconcile: func(route *subscriptionBalanceTest) { route.apply(nil) },
		},
		{
			name:  "changed source",
			apply: func(route *subscriptionBalanceTest) { route.update("source-b", route.tags[1]) },
		},
		{
			name: "remapped connection during a rejected same-source change",
			apply: func(route *subscriptionBalanceTest) {
				route.update("source-a", route.tags[1])
				for i := range 48 {
					route.expect(fmt.Sprintf("site%d.example", i), "second")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			route := newSubscriptionBalanceTest(t, "sticky-session", nil)
			route.update("source-a", route.tags[0])
			for i := range 48 {
				route.expect(fmt.Sprintf("site%d.example", i), "first")
			}
			restore := route.engine.SubscriptionBalanceCheckpoint()
			test.apply(route)
			restore()
			if test.reconcile != nil {
				test.reconcile(route)
			}
			route.update("source-a", route.tags...)
			for i := range 48 {
				route.expect(fmt.Sprintf("site%d.example", i), "first")
			}
		})
	}
}
