package daemon

import (
	"cmp"
	"context"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

// CompileConnectionSettings snapshots only the catalog needed to construct the
// actual outbound graph for a connection settings preflight.
func (d *Daemon) CompileConnectionSettings(cfg *model.Config) ([]byte, error) {
	d.mu.Lock()
	subs := d.subscriptionCompileInputLocked()
	d.mu.Unlock()
	return compile.ConnectionSettingsConfig(compile.Input{Config: cfg, Subscriptions: subs})
}

// ConnectionGroupMembers decodes the saved group using the compiled profile
// shape so disabled groups also retain their declared members.
func ConnectionGroupMembers(ctx context.Context, conn model.Connection) []string {
	if conn.Outbound == nil {
		return nil
	}
	conn.Disabled = false
	raw, err := compile.ConnectionValidationConfig(&model.Config{Connections: []model.Connection{conn}})
	if err != nil {
		return nil
	}
	return engine.DeclaredGroupMembers(ctx, raw)
}

// ConnectionObservation describes reachability of the profile and the static
// class of its routing target, which can include a reserve selector.
type ConnectionObservation struct {
	Disabled, Available, HTTPS bool
	Checked                    time.Time
	LatencyMS                  int64
	Class                      stats.TargetClass
	TrafficGroup               bool
	TrafficMembers             []string
}

// ConnectionHealth takes a small snapshot for the displayed ID without cloning
// all the profiles, rule groups and subscription settings at each poll.
func (d *Daemon) ConnectionHealth(id string) (ConnectionObservation, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil {
		return ConnectionObservation{}, false
	}
	i := slices.IndexFunc(d.cfg.Connections, func(conn model.Connection) bool { return conn.ID == id })
	if i < 0 {
		return ConnectionObservation{}, false
	}
	conn := d.cfg.Connections[i]
	scheme, _, _ := strings.Cut(d.cfg.Failover.URL, ":")
	result := ConnectionObservation{
		Disabled: conn.Disabled, HTTPS: strings.EqualFold(scheme, "https"),
		Class: d.eng.TargetClass(cmp.Or(d.targetAliases[id], id)),
	}
	if conn.Type == model.ConnSingBox {
		kind, _ := conn.Outbound["type"].(string)
		configuredGroup := kind == "selector"
		// Ordinary disabled profiles also have selector stubs. Their traffic
		// history belongs to the original profile ID.
		if !conn.Disabled || configuredGroup {
			result.TrafficMembers, result.TrafficGroup = d.eng.TrafficMembers(id)
			result.TrafficGroup = result.TrafficGroup || configuredGroup
		}
	}
	if h := d.health[id]; !result.Disabled && h != nil && h.known {
		result.Available, result.Checked, result.LatencyMS = h.ok, h.checked, h.latency.Milliseconds()
	}
	return result, true
}

// CheckConnectionIfCurrent performs the configured reachability probe through
// the saved profile itself. It publishes a result only while the same config
// and engine remain current, and never exposes a dial error to a UI client.
func (d *Daemon) CheckConnectionIfCurrent(ctx context.Context, id, revision string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	release, err := acquireDiagnosticSlot(probeCtx)
	if err != nil {
		return err
	}
	defer release()

	d.mu.Lock()
	if !d.matchesConfigRevisionLocked(revision) {
		d.mu.Unlock()
		return model.ErrConfigChanged
	}
	cfg := d.cfg
	if !connectionEnabled(cfg, id) {
		d.mu.Unlock()
		return ErrDiagnosticConnection
	}
	outbound, engineCtx, ok := d.eng.Outbound(id)
	d.mu.Unlock()
	if !ok {
		return ErrDiagnosticConnection
	}

	result := observeProbe(probeCtx, engineCtx, outbound, cfg.Failover.URL)
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg != cfg {
		return model.ErrConfigChanged
	}
	if engineCtx.Err() != nil {
		return ErrDiagnosticConnection
	}
	message := ""
	if result.err != nil {
		message = "connection probe failed"
	}
	d.recordProbeLocked(id, result, message)
	return nil
}

// ConnectionTraffic exposes only the counters needed for the connection page.
func (d *Daemon) ConnectionTraffic(id string) (int, []stats.Point) {
	return d.stats.ConnectionTraffic(id)
}

// discardReplacedManualHealthLocked runs before activation with rollback's
// health snapshot in place. Traffic is retired only after a removal commits.
func (d *Daemon) discardReplacedManualHealthLocked(previous, next *model.Config) []string {
	if previous == nil || len(previous.Connections) == 0 {
		return nil
	}
	current := make(map[string]*model.Connection, len(next.Connections))
	for i := range next.Connections {
		conn := &next.Connections[i]
		current[conn.ID] = conn
	}
	var removed []string
	for _, old := range previous.Connections {
		conn := current[old.ID]
		if conn == nil {
			removed = append(removed, old.ID)
			delete(d.health, old.ID)
			continue
		}
		if d.health[old.ID] == nil {
			continue
		}
		// Changing a label or the reserve leaves the exact probe target intact.
		old.Name, old.Fallback = conn.Name, conn.Fallback
		if previous.Failover.URL != next.Failover.URL || !reflect.DeepEqual(old, *conn) {
			delete(d.health, old.ID)
		}
	}
	return removed
}
