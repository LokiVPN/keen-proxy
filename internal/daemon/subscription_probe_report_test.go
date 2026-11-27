package daemon

import (
	"reflect"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestProbeReportWaitsForFreshProbesAndRateLimits(t *testing.T) {
	const id = "sample"
	fetched := time.Unix(1_800_000_000, 0)
	nodes := []subscription.Node{{ID: "fast", Line: 0}, {ID: "slow", Line: 3}, {ID: "local", Line: 4}}
	d := &Daemon{
		health:        map[string]*health{},
		subscriptions: subscriptionRuntime{states: map[string]appliedSubscription{id: {}}},
	}
	tag := func(node string) string { return model.ManagedTarget(id, node) }
	d.health[tag("fast")] = &health{known: true, ok: true, latency: 85 * time.Millisecond, checked: fetched.Add(-time.Minute)}

	d.queueProbeReportLocked(id, subscription.Result{Nodes: nodes}, fetched)
	if d.subscriptions.states[id].probeReport != nil {
		t.Fatal("a delivery without Probe-Report queued a report")
	}
	d.queueProbeReportLocked(id, subscription.Result{Nodes: nodes, ProbeReportURL: "https://provider.example/sub/_probe/g/report"}, fetched)
	if got, _ := d.dueProbeReportLocked(fetched.Add(time.Minute)); got != "" {
		t.Fatal("a report was sent with only stale results")
	}

	d.health[tag("fast")].checked = fetched.Add(time.Second)
	d.health[tag("slow")] = &health{known: true, err: "check timed out", checked: fetched.Add(time.Second)}
	d.health[tag("local")] = &health{known: true, err: "subscription node is not running", checked: fetched.Add(time.Second)}
	if got, _ := d.dueProbeReportLocked(fetched.Add(2 * time.Minute)); got != "" {
		t.Fatal("a report was sent before every node had a reportable result or the wait expired")
	}
	got, report := d.dueProbeReportLocked(fetched.Add(probeReportWait))
	want := map[int]subscription.ProbeResult{0: {Verdict: "ok", DelayMS: 85}, 3: {Verdict: "timeout"}}
	if got != id || report.URL != "https://provider.example/sub/_probe/g/report" || !reflect.DeepEqual(report.Results, want) {
		t.Fatalf("unexpected report %q %+v", got, report)
	}
	if again, _ := d.dueProbeReportLocked(fetched.Add(probeReportWait)); again != "" {
		t.Fatal("a claimed report was sent twice")
	}

	d.queueProbeReportLocked(id, subscription.Result{Nodes: nodes, ProbeReportURL: report.URL}, fetched.Add(probeReportWait+time.Minute))
	if d.subscriptions.states[id].probeReport != nil {
		t.Fatal("a refresh within the report interval queued another report")
	}
}
