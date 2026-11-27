package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	// probeReportInterval keeps one source within the provider's two attempts
	// per ten minutes, including manual refreshes.
	probeReportInterval = 10 * time.Minute
	// probeReportWait bounds the wait for fresh probes inside the 15-minute grant.
	probeReportWait = 10 * time.Minute
)

// pendingProbeReport is the delivery that asked for a report, held until its
// nodes have been probed after the fetch or the wait expires.
type pendingProbeReport struct {
	url   string
	at    time.Time
	nodes []subscription.Node
}

// queueProbeReportLocked records a report request from a successful refresh.
func (d *Daemon) queueProbeReportLocked(id string, result subscription.Result, at time.Time) {
	state, exists := d.subscriptions.states[id]
	if !exists || result.ProbeReportURL == "" || at.Sub(state.probeReported) < probeReportInterval {
		return
	}
	state.probeReport = &pendingProbeReport{url: result.ProbeReportURL, at: at, nodes: result.Nodes}
	d.subscriptions.states[id] = state
}

// dueProbeReportLocked claims one report whose nodes all have a probe result
// from after the fetch, or whose wait has expired. Only fresh results are sent.
func (d *Daemon) dueProbeReportLocked(now time.Time) (string, subscription.ProbeReport) {
	for id, state := range d.subscriptions.states {
		pending := state.probeReport
		if pending == nil {
			continue
		}
		results := make(map[int]subscription.ProbeResult, len(pending.nodes))
		for _, node := range pending.nodes {
			if result, ok := probeReportResult(d.health[model.ManagedTarget(id, node.ID)], pending.at); ok {
				results[node.Line] = result
			}
		}
		if len(results) < len(pending.nodes) && now.Sub(pending.at) < probeReportWait {
			continue
		}
		state.probeReport = nil
		if len(results) > 0 {
			state.probeReported = now
		}
		d.subscriptions.states[id] = state
		if len(results) > 0 {
			return id, subscription.ProbeReport{URL: pending.url, Results: results}
		}
	}
	return "", subscription.ProbeReport{}
}

// probeReportResult maps an HTTP probe through the node to a report verdict.
// Local failures that say nothing about the route are omitted (untested).
func probeReportResult(h *health, since time.Time) (subscription.ProbeResult, bool) {
	if h == nil || !h.known || h.checked.Before(since) {
		return subscription.ProbeResult{}, false
	}
	switch {
	case h.ok:
		return subscription.ProbeResult{Verdict: "ok", DelayMS: min(h.latency.Milliseconds(), 120_000)}, true
	case h.err == "check timed out":
		return subscription.ProbeResult{Verdict: "timeout"}, true
	case h.err == "check cancelled", h.err == "subscription node is not running", h.err == "subscription node test could not start":
		return subscription.ProbeResult{}, false
	default:
		return subscription.ProbeResult{Verdict: "network_error"}, true
	}
}

// sendProbeReport runs outside d.mu; a failed report is audited, not retried.
func (d *Daemon) sendProbeReport(ctx context.Context, id string, report subscription.ProbeReport) {
	accepted, err := d.subscriptions.fetcher.SendProbeReport(ctx, report)
	if err != nil {
		d.audit("system", "Subscription probe report failed", id, "warn", err.Error())
		return
	}
	d.audit("system", "Subscription probe report sent", id, "ok", fmt.Sprintf("%d of %d results accepted", accepted, len(report.Results)))
}
