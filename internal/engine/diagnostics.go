package engine

import (
	"context"
	"errors"

	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/sagernet/sing-box/adapter"
)

// ErrDiagnosticPath means a probe would require a reserve or a dependent dial.
var ErrDiagnosticPath = errors.New("diagnostic path requires a detour or reserve")

// DiagnosticLeaf pins the selected concrete TCP outbound in the current
// instance. Its caller can dial that leaf even if a selector changes afterward.
func (e *Engine) DiagnosticLeaf(tag string, excluded func(string) bool) (adapter.Outbound, context.Context, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil {
		return nil, nil, nil
	}
	out, blocked := stats.SelectedTCPLeaf(e.box.Outbound(), tag, excluded)
	if blocked {
		return nil, nil, ErrDiagnosticPath
	}
	switch stats.TargetClassOf(e.ctx, out) {
	case stats.TargetDirect, stats.TargetVPN:
		if len(out.Dependencies()) != 0 || !independentDiagnosticLeaf(e.ctx, e.current, out.Tag()) {
			return nil, nil, ErrDiagnosticPath
		}
		return out, e.ctx, nil
	default:
		return nil, nil, nil
	}
}
