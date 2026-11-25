package daemon

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

// ConnectionObservation describes reachability of the profile and the static
// class of its routing target, which can include a reserve selector.
type ConnectionObservation struct {
	Disabled, Available, HTTPS bool
	Checked                    time.Time
	LatencyMS                  int64
	Class                      stats.TargetClass
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
	scheme, _, _ := strings.Cut(d.cfg.Failover.URL, ":")
	result := ConnectionObservation{
		Disabled: d.cfg.Connections[i].Disabled, HTTPS: strings.EqualFold(scheme, "https"),
		Class: d.eng.TargetClass(cmp.Or(d.targetAliases[id], id)),
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

	latency, probeErr := probeOutbound(probeCtx, engineCtx, outbound, cfg.Failover.URL)
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
	h := d.health[id]
	if h == nil {
		h = &health{}
		d.health[id] = h
	}
	message := ""
	if probeErr != nil {
		message = "connection probe failed"
	}
	h.record(probeErr == nil, latency, message, time.Now())
	return nil
}

// ConnectionTraffic exposes only the counters needed for the connection page.
func (d *Daemon) ConnectionTraffic(id string) (int, []stats.Point) {
	return d.stats.ConnectionTraffic(id)
}
