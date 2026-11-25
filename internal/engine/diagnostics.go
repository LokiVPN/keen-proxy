package engine

import (
	"context"
	"errors"

	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/sagernet/sing-box/adapter"
)

// ErrDiagnosticPath means a probe would require a reserve or a dependent dial.
var ErrDiagnosticPath = errors.New("diagnostic path requires a detour or reserve")

// DiagnosticBalancePath reads an eligible TCP member from the applied pool.
// Diagnostics never advance rotation or assign a sticky session.
func (e *Engine) DiagnosticBalancePath(tag string) (member string, onReserve bool) {
	out, _, _ := e.Outbound(tag)
	balance, ok := out.(*subscriptionBalance)
	if !ok {
		return "", false
	}
	if pool := balance.pool.Load(); pool != nil && len(pool.tcp) > 0 {
		return pool.tcp[0].outbound.Tag(), false
	}
	return balance.block.Tag(), true
}

// DiagnosticLeaf pins the selected concrete TCP outbound in the current
// instance. A skipped leaf describes the route but must not be dialed.
func (e *Engine) DiagnosticLeaf(tag string, isReserve func(group, member string) bool) (leaf adapter.Outbound, core context.Context, skipped bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil {
		return nil, nil, false, nil
	}
	manager := e.box.Outbound()
	out, reserve := stats.SelectedTCPLeaf(manager, tag, isReserve)
	if out == nil {
		return nil, nil, false, nil
	}
	class := stats.TargetClassOf(e.ctx, out)
	if reserve || (class == stats.TargetDirect || class == stats.TargetBlock) && stats.HasAlternativeTargetLeaf(manager, tag, out.Tag()) {
		return out, nil, true, nil
	}
	switch class {
	case stats.TargetDirect, stats.TargetVPN:
		if len(out.Dependencies()) != 0 || !independentDiagnosticLeaf(e.ctx, e.current, out.Tag()) {
			return nil, nil, false, ErrDiagnosticPath
		}
		return out, e.ctx, false, nil
	default:
		return nil, nil, false, nil
	}
}
