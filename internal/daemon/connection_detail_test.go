package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/ui"
	"github.com/sagernet/sing-box/adapter"
)

func TestConnectionProbeChecksTheAppliedProfile(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodHead || r.URL.Path != "/check" {
			t.Error("unexpected probe request")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Failover.URL = server.URL + "/check"
	cfg.Connections = []model.Connection{
		{ID: "standalone-direct", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
		{ID: "blocked", Type: model.ConnSingBox, Fallback: model.TargetDirect, Outbound: map[string]any{"type": "block"}},
		{ID: "mixed", Type: model.ConnLink, Fallback: model.TargetDirect, Link: "socks5://example.test:1080"},
		{ID: "disabled", Type: model.ConnSingBox, Disabled: true, Outbound: map[string]any{"type": "direct"}},
	}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{})
	t.Cleanup(d.shutdown)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	rev := model.ConfigRevision(d.Config())
	if err := d.CheckConnectionIfCurrent(t.Context(), "standalone-direct", "stale"); !errors.Is(err, model.ErrConfigChanged) {
		t.Fatalf("stale probe returned %v", err)
	}
	if err := d.CheckConnectionIfCurrent(t.Context(), "disabled", rev); !errors.Is(err, ErrDiagnosticConnection) {
		t.Fatalf("disabled probe returned %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("a stale or disabled entry reached the server")
	}
	if err := d.CheckConnectionIfCurrent(t.Context(), "standalone-direct", rev); err != nil {
		t.Fatal(err)
	}
	got, ok := d.ConnectionHealth("standalone-direct")
	if !ok || !got.Available || got.Checked.IsZero() || got.HTTPS || got.Class != stats.TargetDirect || requests.Load() != 1 {
		t.Fatalf("unexpected successful probe observation: %+v; requests = %d", got, requests.Load())
	}

	if !d.eng.Select(compile.FailoverTagPrefix+"blocked", model.TargetDirect) {
		t.Fatal("could not select the direct reserve")
	}
	if err := d.CheckConnectionIfCurrent(t.Context(), "blocked", rev); err != nil {
		t.Fatal(err)
	}
	got, ok = d.ConnectionHealth("blocked")
	if !ok || got.Available || got.Checked.IsZero() || requests.Load() != 1 {
		t.Fatal("the probe succeeded through the selected reserve")
	}
	if health, _ := d.ConnectionHealth("mixed"); health.Class != stats.TargetMixed {
		t.Fatalf("mixed target has static class %v", health.Class)
	}
	if rev != model.ConfigRevision(d.Config()) {
		t.Fatal("probing changed the configuration")
	}
}

func TestConnectionProbeNewerCheckSurvivesDelayedBatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()
	previousRequest := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) != 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
		} else {
			_ = conn.Close()
		}
		close(previousRequest)
	}))
	defer server.Close()

	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	slowStarted, releaseSlow := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(slowStarted)
		select {
		case <-releaseSlow:
		case <-ctx.Done():
		}
	}()
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Failover.URL = server.URL
	cfg.Connections = []model.Connection{
		{ID: "recovering", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
		{ID: "slow", Type: model.ConnLink, Link: "socks5://" + proxy.Addr().String()},
	}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{})
	t.Cleanup(d.shutdown)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	batchDone := make(chan struct{})
	go func() { defer close(batchDone); d.runFailover(ctx) }()
	defer func() { cancel(); <-batchDone }()
	for _, started := range []chan struct{}{previousRequest, slowStarted} {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("the two periodic probes did not start")
		}
	}
	if err := d.CheckConnectionIfCurrent(ctx, "recovering", model.ConfigRevision(d.Config())); err != nil {
		t.Fatal(err)
	}
	newer, _ := d.ConnectionHealth("recovering")
	if !newer.Available || newer.Checked.IsZero() {
		t.Fatal("manual probe did not record success")
	}
	close(releaseSlow)
	waitForDetailObservation(t, ctx, func() bool {
		slow, _ := d.ConnectionHealth("slow")
		return !slow.Checked.IsZero()
	})
	got, _ := d.ConnectionHealth("recovering")
	if !got.Available || !got.Checked.Equal(newer.Checked) {
		t.Fatal("the old periodic failure replaced a newer manual success")
	}
	current := d.Config()
	rev := model.ConfigRevision(current)
	current.Connections[0].Outbound["type"] = "block"
	if err := d.ApplyIfCurrent(ctx, current, rev); err != nil {
		t.Fatal(err)
	}
	if health, _ := d.ConnectionHealth("recovering"); !health.Checked.IsZero() {
		t.Fatal("a replacement inherited the old profile's check result")
	}
	if err := d.CheckConnectionIfCurrent(ctx, "recovering", model.ConfigRevision(d.Config())); err != nil {
		t.Fatal(err)
	}
	if health, _ := d.ConnectionHealth("recovering"); health.Available || !health.Checked.After(newer.Checked) {
		t.Fatal("the replacement did not receive its own newer check result")
	}
}

func TestConnectionDetailSelectorTrafficLinksLeafPages(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Connections = []model.Connection{
		{ID: "route", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"nested", "balancer"}}},
		{ID: "nested", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"leaf"}}},
		{ID: "balancer", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "urltest", "outbounds": []string{"leaf"}, "url": "http://127.0.0.1:1/check",
		}},
		{ID: "leaf", Name: "Station egress", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
	}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{})
	t.Cleanup(d.shutdown)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	openDetailTraffic(t, d, "work.example", "route", "nested", "leaf")
	openDetailTraffic(t, d, "balancing.example", "route", "balancer")
	h := ui.New(connectionDetailTestDeps{d: d}, ui.Options{Role: func(*http.Request) ui.Role { return ui.RoleView }})
	get := func(path string) string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s returned HTTP %d", path, w.Code)
		}
		return w.Body.String()
	}
	body := get("/connections/id/route")
	if !strings.Contains(body, `href="/connections/id/leaf"`) || !strings.Contains(body, "Station egress") ||
		!strings.Contains(body, `href="/connections/id/balancer"`) ||
		!strings.Contains(body, "Traffic is recorded on member outbounds") ||
		strings.Contains(body, "Active connections") || strings.Contains(body, "No site traffic recorded") {
		t.Error("selector page did not direct the user to the real member traffic")
	}
	for _, part := range []string{"speed", "hosts"} {
		body = get("/fragments/connection/route/" + part)
		if !strings.Contains(body, "Traffic is recorded on member outbounds") {
			t.Errorf("selector %s fragment implied a standalone traffic history", part)
		}
	}
	body = get("/connections/id/leaf")
	if !strings.Contains(body, "work.example") || !strings.Contains(body, "1 KB") {
		t.Error("member page is missing the tracked flow and its bytes")
	}
	if body = get("/connections/id/balancer"); !strings.Contains(body, "balancing.example") {
		t.Error("member that resolves at dial time lost its own traffic")
	}
}

func TestConnectionReserveDependencyCycleKeepsRunningCore(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Connections = []model.Connection{
		{ID: "primary", Type: model.ConnLink, Link: "socks5://primary.example:1080", Disabled: true, Fallback: model.TargetDirect},
		{ID: "dependent", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "socks", "server": "dependent.example", "server_port": 1080, "detour": "primary",
		}},
	}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{})
	t.Cleanup(d.shutdown)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	_, before, ok := d.eng.Outbound("dependent")
	if !ok {
		t.Fatal("the starting graph was not active")
	}
	draft := d.Config()
	rev := model.ConfigRevision(draft)
	draft.Connections[0].Fallback = "dependent"
	if err := d.ApplyIfCurrent(t.Context(), draft, rev); err == nil {
		t.Fatal("daemon accepted a circular dependency")
	}
	_, after, ok := d.eng.Outbound("dependent")
	if !ok || after != before || before.Err() != nil || model.ConfigRevision(d.Config()) != rev {
		t.Fatal("rejecting the circular dependency restarted the applied core or changed its config")
	}
}

func TestConnectionDetailReusedIDStartsWithEmptyTraffic(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Connections = []model.Connection{{ID: "repeat", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}}}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), &gateRunner{})
	t.Cleanup(d.shutdown)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	tracked := openDetailTraffic(t, d, "original.example", "repeat")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	go d.stats.Run(ctx)
	waitForDetailObservation(t, ctx, func() bool {
		_, series := d.ConnectionTraffic("repeat")
		return len(series) > 0 && series[0].Down > 0
	})

	current := d.Config()
	rev := model.ConfigRevision(current)
	current.Connections[0] = model.Connection{ID: "repeat", Type: model.ConnLink, Link: "socks5://replacement.example:1080"}
	if err := d.ApplyIfCurrent(t.Context(), current, rev); err != nil {
		t.Fatal(err)
	}
	if hosts, n := d.Hosts("repeat", "", 10); n != 1 || hosts[0].Down != 1024 {
		t.Fatal("same-ID replacement discarded the existing traffic")
	}
	out, oldEngine, ok := d.eng.Outbound("repeat")
	if !ok {
		t.Fatal("replacement did not reach the running engine")
	}

	current = d.Config()
	replacement := current.Connections[0]
	rev = model.ConfigRevision(current)
	current.Connections = nil
	if err := d.ApplyIfCurrent(t.Context(), current, rev); err != nil {
		t.Fatal(err)
	}
	current = d.Config()
	rev = model.ConfigRevision(current)
	current.Connections = []model.Connection{replacement}
	if err := d.ApplyIfCurrent(t.Context(), current, rev); err != nil {
		t.Fatal(err)
	}
	if n, series := d.ConnectionTraffic("repeat"); n != 0 || len(series) > 0 {
		t.Error("reused ID still has the deleted profile's connection count or samples")
	}
	if _, n := d.Hosts("repeat", "", 10); n != 0 {
		t.Error("reused ID still has the deleted profile's site history")
	}

	lateDevice, lateInbound := net.Pipe()
	defer lateDevice.Close()
	late := d.stats.RoutedConnection(oldEngine, lateInbound, adapter.InboundContext{Domain: "late.example"}, nil, out)
	defer late.Close()
	openDetailTraffic(t, d, "new.example", "repeat")
	_ = tracked.Close()
	hosts, n := d.Hosts("repeat", "", 10)
	if active, _ := d.ConnectionTraffic("repeat"); n != 1 || hosts[0].Host != "new.example" || active != 1 {
		t.Error("a late flow or close from the old engine changed the new profile's history")
	}
}

func openDetailTraffic(t *testing.T, d *Daemon, host string, tags ...string) net.Conn {
	t.Helper()
	var ctx context.Context
	var chain []adapter.Outbound
	for _, tag := range tags {
		out, engineCtx, ok := d.eng.Outbound(tag)
		if !ok {
			t.Fatalf("missing test outbound %s", tag)
		}
		ctx = engineCtx
		chain = append(chain, out)
	}
	device, inbound := net.Pipe()
	t.Cleanup(func() { _ = device.Close(); _ = inbound.Close() })
	tracked := d.stats.RoutedConnection(ctx, inbound, adapter.InboundContext{Domain: host, OutboundChain: chain}, nil, chain[0])
	t.Cleanup(func() { _ = tracked.Close() })
	received := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		_, err := device.Read(buf)
		received <- err
	}()
	if _, err := tracked.Write(make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	return tracked
}

func waitForDetailObservation(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for the test observation")
		case <-tick.C:
		}
	}
}

type connectionDetailTestDeps struct {
	ui.Deps
	d *Daemon
}

func (f connectionDetailTestDeps) Config() *model.Config { return f.d.Config() }

func (f connectionDetailTestDeps) ValidateConnectionSettings(_ context.Context, cfg *model.Config) error {
	return cfg.Validate()
}

func (f connectionDetailTestDeps) ConnectionHealth(id string) (ui.ConnectionHealth, bool) {
	observation, ok := f.d.ConnectionHealth(id)
	return ui.ConnectionHealth(observation), ok
}

func (f connectionDetailTestDeps) ConnectionTraffic(id string) (int, []stats.Point) {
	return f.d.ConnectionTraffic(id)
}

func (f connectionDetailTestDeps) ConnectionHosts(id string, limit int) ([]stats.Host, int) {
	return f.d.Hosts(id, "", limit)
}
