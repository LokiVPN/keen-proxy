package daemon

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
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
