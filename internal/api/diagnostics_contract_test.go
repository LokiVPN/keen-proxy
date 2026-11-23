package api

import (
	"context"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// diagnosticContextProbe observes the RPC boundary without opening network connections.
type diagnosticContextProbe struct {
	*fakeDaemon
	deadline  bool
	remaining time.Duration
}

func (p *diagnosticContextProbe) DiagnosticChecks(ctx context.Context, id string) (daemon.DiagnosticReport, error) {
	deadline, ok := ctx.Deadline()
	p.deadline, p.remaining = ok, time.Until(deadline)
	return daemon.DiagnosticReport{Connection: id}, nil
}

func TestDiagnosticRPCProvidesUsableBoundedContext(t *testing.T) {
	s, fake := newServer()
	fake.cfg.Connections = []model.Connection{{ID: "one", Type: model.ConnLink}}
	probe := &diagnosticContextProbe{fakeDaemon: fake}
	s.D = probe
	w := do(t, s.Handler(), "POST", "/api/diagnostics/check", `{"connection":"one"}`, "secret", local)
	if w.Code != 200 || !probe.deadline || probe.remaining <= time.Second || probe.remaining > 25*time.Second {
		t.Fatalf("unusable diagnostic budget: status=%d deadline=%v remaining=%s", w.Code, probe.deadline, probe.remaining)
	}
}
