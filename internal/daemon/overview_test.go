package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

func TestOverviewRedactsLegacySubscriptionSnapshot(t *testing.T) {
	const privateLink = "https://provider.example/catalog?account=synthetic-token&device=router"
	const echoedLink = "https://provider.example/catalog?device=router&account=synthetic-token"
	const redirectedPath = "https://provider.example/catalog/legacy-private-path"
	source := subscription.Source{ID: "sample", URL: privateLink}
	d := newOverviewTestDaemon(t, source)
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst + "\n" + subscriptionSecond})
	d.subscriptions.fetcher = subscription.NewFetcher("", provider)
	result := d.subscriptions.fetcher.Fetch(t.Context(), source)
	if result.State != subscription.StateReady || len(result.Nodes) != 2 {
		t.Fatal("fixture did not produce two valid node IDs")
	}
	nodes := result.Nodes
	nodes[0].Name = "First " + echoedLink
	lastSuccess := time.Now().Add(-time.Hour)
	snapshot := subscriptionSnapshot{
		Nodes: nodes, LastSuccess: lastSuccess,
		Metadata: subscription.Metadata{
			Title: "Test VPN " + echoedLink, Announce: "Maintenance " + echoedLink,
			SupportURL: "https://help.example/?next=" + url.QueryEscape(echoedLink),
			ProfileURL: redirectedPath,
			Usage:      &subscription.Usage{Total: 200 << 30, Expire: time.Now().Add(48 * time.Hour).Unix()},
		},
	}
	file := d.subscriptionSnapshotPath(d.cfg)
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]subscriptionSnapshot{subscriptionFingerprint(source): snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	d.loadSubscriptionSnapshotsLocked(t.Context(), d.cfg)
	status := d.Subscriptions()[0]
	if len(status.Nodes) != 2 || status.Nodes[0].ID != nodes[0].ID || status.Nodes[1].Name != "Second" ||
		status.LastSuccess == nil || !status.LastSuccess.Equal(lastSuccess) || status.Metadata.Usage.Expire != snapshot.Metadata.Usage.Expire {
		t.Fatal("restoring the snapshot changed usable nodes or the last update and expiry")
	}
	if status.Metadata.SupportURL != "" || status.Metadata.ProfileURL != "" {
		t.Error("restoring the snapshot exposed an unverified metadata link")
	}
	if restored := d.subscriptionCompileInputLocked()[source.ID]; len(restored) != 2 || restored[0].Link != nodes[0].Link {
		t.Error("sanitizing the snapshot changed its routing data")
	}
	page := viewOverview(t, d)
	for _, want := range []string{"Test VPN [redacted]", "Maintenance [redacted]", "First [redacted]", "Second"} {
		if !strings.Contains(page, want) {
			t.Errorf("view overview is missing safe text %q", want)
		}
	}
	if strings.Contains(page, "synthetic-token") || strings.Contains(page, "legacy-private-path") || provider.requests.Load() != 1 {
		t.Error("view overview exposed a cached credential or fetched the provider again")
	}
}

func TestOverviewKeepsExpiryAfterFailedSubscriptionRefresh(t *testing.T) {
	source := subscription.Source{ID: "sample", URL: "https://provider.example/catalog"}
	d := newOverviewTestDaemon(t, source)
	now := time.Now()
	lastSuccess := now.Add(-24 * time.Hour)
	expiry := now.Add(-time.Hour).Unix()
	request := &subscriptionRefresh{source: source}
	d.subscriptions.states = map[string]appliedSubscription{source.ID: {
		source: source, request: request,
		snapshot: subscriptionSnapshot{
			LastSuccess: lastSuccess, Nodes: []subscription.Node{{ID: "123456789abcdef0123456789abcdef0", Name: "Cached node"}},
			Metadata: subscription.Metadata{
				Title: "Cached VPN", ProfileURL: "https://account.example/renew",
				Usage: &subscription.Usage{Total: 200 << 30, Expire: expiry},
			},
		},
	}}
	d.finishSubscriptionRefreshLocked(request, subscriptionAttempt{at: now, result: subscription.Result{
		State: subscription.StateHTTPError, Error: "Synthetic provider error",
		Metadata: subscription.Metadata{Announce: "Provider notice"},
	}})
	status := d.Subscriptions()[0]
	if status.State != subscription.StateHTTPError || len(status.Nodes) != 1 || status.LastSuccess == nil || !status.LastSuccess.Equal(lastSuccess) ||
		status.Metadata.Usage == nil || status.Metadata.Usage.Expire != expiry {
		t.Error("a failed refresh discarded cached subscription facts")
	}
	page := viewOverview(t, d)
	for _, want := range []string{">Expired</span>", "Last update failed", `href="https://account.example/renew"`, "Provider notice", "Cached VPN"} {
		if !strings.Contains(page, want) {
			t.Errorf("view overview is missing %q after a failed refresh", want)
		}
	}
	if strings.Contains(page, ">Active</span>") || strings.Contains(page, "Synthetic provider error") {
		t.Error("the page presented a failed refresh as active or printed a raw error")
	}

	state := d.subscriptions.states[source.ID]
	state.request = request
	d.subscriptions.states[source.ID] = state
	d.finishSubscriptionRefreshLocked(request, subscriptionAttempt{at: now.Add(time.Second), result: subscription.Result{
		State:    subscription.StateHTTPError,
		Metadata: subscription.Metadata{Usage: &subscription.Usage{Download: 100}},
	}})
	if usage := d.Subscriptions()[0].Metadata.Usage; usage == nil || usage.Expire != expiry || usage.Total != 200<<30 {
		t.Error("partial usage from a failed refresh erased the last accepted quota or expiry")
	}
}

func TestRoutingStatusChecksTheRunningEngine(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Connections = []model.Connection{{ID: "local-egress", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}}}
	cfg.Networks = []model.Network{{Name: "Home", CIDR: "192.0.2.0/24", Mode: model.ModeFull, Target: "local-egress"}}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{})
	t.Cleanup(d.shutdown)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	d.neighbors = map[string]netip.Addr{"02:00:00:00:00:01": netip.MustParseAddr("192.0.2.2")}
	if status := d.RoutingStatus(); !status.Ready || status.Devices != 1 || status.ManagedDevices != 1 || status.TargetClasses["local-egress"] != stats.TargetDirect {
		t.Fatal("the running core and covered device should be visible with the custom direct target")
	}
	if err := d.eng.Close(); err != nil {
		t.Fatal(err)
	}
	if status := d.RoutingStatus(); !d.planOn || d.planPending || status.Ready || status.ManagedDevices != 0 {
		t.Fatal("the installed plan reported readiness with no running engine")
	}
}

func TestOverviewUsesStaticLeavesOfRawGroups(t *testing.T) {
	const target = "test-route"
	for _, tc := range []struct {
		name, banner, detail, summary string
		direct, mixed, roundRobin     bool
	}{
		{"five selectors ending in direct", "Direct connection", "routes directly", "Direct connection", true, false, false},
		{"mixed round robin", "Connection routing", "Traffic follows connection Test route", "Traffic follows connection Test route", false, true, true},
		{"mixed selector", "Connection routing", "Traffic follows connection Test route", "Traffic follows connection Test route", false, true, false},
		{"pure tunnel selector", "Working", "Test route", "All traffic through VPN", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holdMemoryLimit(t)
			cfg := quietConfig(t)
			cfg.Networks = []model.Network{{Name: "Home", CIDR: "192.0.2.0/24", Mode: model.ModeFull, Target: target}}
			if tc.direct {
				id := target
				for i := 1; i <= 5; i++ {
					next := fmt.Sprintf("selector-%d", i)
					if i == 5 {
						next = model.TargetDirect
					}
					cfg.Connections = append(cfg.Connections, model.Connection{ID: id, Name: "Test route", Type: model.ConnSingBox,
						Outbound: map[string]any{"type": "selector", "outbounds": []string{next}}})
					id = next
				}
			} else {
				group := map[string]any{"type": "selector", "outbounds": []string{"vpn"}}
				if tc.mixed {
					group["outbounds"] = []string{model.TargetDirect, "vpn"}
					if tc.roundRobin {
						group["type"], group["mode"], group["url"] = "urltest", "round_robin", "http://127.0.0.1:1/generate_204"
					} else {
						group["default"] = "vpn"
					}
				}
				cfg.Connections = []model.Connection{
					{ID: "vpn", Type: model.ConnLink, Link: subscriptionFirst},
					{ID: target, Name: "Test route", Type: model.ConnSingBox, Outbound: group},
				}
			}
			d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{})
			t.Cleanup(d.shutdown)
			if err := d.Apply(t.Context(), cfg); err != nil {
				t.Fatal(err)
			}
			d.neighbors = map[string]netip.Addr{"02:00:00:00:00:01": netip.MustParseAddr("192.0.2.2")}
			d.health[target] = &health{known: true, ok: true, checked: time.Now(), latency: 35 * time.Millisecond}
			page := viewOverview(t, d)
			banner, _, _ := strings.Cut(page, `aria-label="KeenProxy sections"`)
			if !strings.Contains(banner, ">"+tc.banner+"</span>") || !strings.Contains(banner, tc.detail) ||
				!strings.Contains(page, `<p class="clip">`+tc.summary) || !strings.Contains(page, "KeenProxy handles 1 of 1 devices") {
				t.Errorf("overview did not show %q with summary %q for the configured leaves", tc.banner, tc.summary)
			}
			if tc.mixed && (strings.Contains(page, "All traffic through VPN") || strings.Contains(page, "Direct connection") ||
				strings.Contains(page, "New devices connect directly by default")) {
				t.Error("mixed target was presented as one type of route")
			}

			d.mu.Lock()
			d.health[target].record(false, 0, "probe failed", time.Now())
			d.mu.Unlock()
			page = viewOverview(t, d)
			banner, _, _ = strings.Cut(page, `aria-label="KeenProxy sections"`)
			if !strings.Contains(banner, `>No connection</span>`) || !strings.Contains(banner, "The main connection is unavailable.") {
				t.Error("overview did not warn about the failed main-connection probe")
			}
			if !strings.Contains(page, `<p class="clip">`+tc.summary) || !strings.Contains(page, "KeenProxy handles 1 of 1 devices") {
				t.Error("the failed probe changed the routing summary or device coverage")
			}
		})
	}
}

func TestOverviewBlockingPaths(t *testing.T) {
	const sourceID = "sample"
	auto := model.ManagedTarget(sourceID, "auto")
	for _, tc := range []struct {
		name, target, reserve, connectionFallback, detail string
	}{
		{"named block reserve", auto, "reject", "", "No subscription node is available."},
		{"built-in block fallback", auto, model.TargetBlock, "", "No subscription node is available."},
		{"block-only selector", "blocking-group", "", "", "The main connection is unavailable."},
		{"blocked active primary with direct failover", "reject", "", model.TargetDirect, "The main connection is unavailable."},
		{"blocked active reserve with direct failover", auto, "reject", model.TargetDirect, "No subscription node is available."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holdMemoryLimit(t)
			cfg := quietConfig(t)
			cfg.Networks = []model.Network{{Name: "Home", CIDR: "192.0.2.0/24", Mode: model.ModeFull, Target: tc.target}}
			cfg.Connections = []model.Connection{
				{ID: "reject", Type: model.ConnSingBox, Fallback: tc.connectionFallback, Outbound: map[string]any{"type": "block"}},
				{ID: "blocking-group", Type: model.ConnSingBox, Outbound: map[string]any{
					"type": "selector", "outbounds": []string{"reject"},
				}},
			}
			if tc.target == auto {
				cfg.Subscriptions = []subscription.Source{{ID: sourceID, URL: "https://provider.example/catalog", Fallback: tc.reserve}}
			}
			d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{})
			t.Cleanup(d.shutdown)
			// A saved source can start with no catalog or probe results.
			d.loadSubscriptionSnapshotsLocked(t.Context(), cfg)
			if err := d.Apply(t.Context(), cfg); err != nil {
				t.Fatal(err)
			}
			page := viewOverview(t, d)
			_, banner, _ := strings.Cut(page, `<div class="overview-status">`)
			banner, _, _ = strings.Cut(banner, `</div>`)
			if !strings.Contains(banner, `class="chip warn">No connection</span>`) || !strings.Contains(banner, tc.detail+"</p>") {
				t.Errorf("overview should show the outage before probing the blocking path, got %s", banner)
			}
		})
	}
}

func newOverviewTestDaemon(t *testing.T, source subscription.Source) *Daemon {
	t.Helper()
	d := New(Options{RuleSetDir: filepath.Join(t.TempDir(), "rules")})
	d.cfg = &model.Config{Subscriptions: []subscription.Source{source}}
	d.cfg.RouteHomeThroughSubscription(source.ID, netip.MustParsePrefix("192.0.2.0/24"))
	return d
}

func viewOverview(t *testing.T, d *Daemon) string {
	t.Helper()
	page := ui.New(overviewTestDeps{d: d}, ui.Options{Role: func(*http.Request) ui.Role { return ui.RoleView }})
	w := httptest.NewRecorder()
	page.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "View only") {
		t.Fatalf("view account's overview returned HTTP %d", w.Code)
	}
	return w.Body.String()
}

type overviewTestDeps struct {
	ui.Deps
	d *Daemon
}

func (v overviewTestDeps) Config() *model.Config { return v.d.Config() }
func (v overviewTestDeps) OverviewStatus() ui.OverviewStatus {
	routing := v.d.RoutingStatus()
	status := ui.OverviewStatus{Ready: routing.Ready, Devices: routing.Devices, ManagedDevices: routing.ManagedDevices,
		Connections: make(map[string]ui.ConnectionStatus)}
	for id, probe := range routing.Health {
		status.Connections[id] = ui.ConnectionStatus{Checked: !probe.Checked.IsZero(), Available: probe.OK, LatencyMS: probe.Latency}
	}
	for id, failover := range routing.Failover {
		connection := status.Connections[id]
		connection.Active = failover.Active
		connection.ActiveClass = routing.ActiveTargetClasses[id]
		status.Connections[id] = connection
	}
	for id, class := range routing.TargetClasses {
		connection := status.Connections[id]
		connection.Class = class
		status.Connections[id] = connection
	}
	return status
}
func (v overviewTestDeps) TrafficSeries() []stats.Point { return nil }

func (v overviewTestDeps) Subscriptions() []ui.AppliedSubscription {
	statuses := v.d.Subscriptions()
	if len(statuses) == 0 {
		return nil
	}
	status := statuses[0]
	sub := ui.AppliedSubscription{
		ID: status.ID, State: status.State, Metadata: status.Metadata, Unavailable: status.Unavailable,
		ActiveNode: status.ActiveNode, SwitchReason: status.SwitchReason,
	}
	if status.LastSuccess != nil {
		sub.LastSuccess = *status.LastSuccess
	}
	for _, node := range status.Nodes {
		sub.Nodes = append(sub.Nodes, ui.SubscriptionNode{ID: node.ID, Name: node.Name, Health: node.Health, LatencyMS: node.LatencyMS})
	}
	return []ui.AppliedSubscription{sub}
}
