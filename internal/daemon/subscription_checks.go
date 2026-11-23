package daemon

import (
	"slices"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

type subscriptionCheckFlags uint8

const (
	checkSingle subscriptionCheckFlags = 1 << iota
	checkCatalog
)

// SubscriptionCheckProgress counts completed probes in one on-demand sweep.
type SubscriptionCheckProgress struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
}

// subscriptionChecks holds one coalesced set of requests for an applied source.
type subscriptionChecks struct {
	pending map[string]subscriptionCheckFlags
	sweep   SubscriptionCheckProgress
}

// CheckSubscription schedules a probe of a saved node, or a sweep of the saved
// catalog when nodeID is empty. The background worker owns all network work.
func (d *Daemon) CheckSubscription(sourceID, nodeID string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, exists := d.subscriptions.states[sourceID]
	nodes := state.snapshot.Nodes
	if !exists || d.closed || d.startupBlocked != nil || len(nodes) == 0 {
		return false
	}
	if nodeID != "" && !slices.ContainsFunc(nodes, func(node subscription.Node) bool { return node.ID == nodeID }) {
		return false
	}
	if state.checks.pending == nil {
		state.checks.pending = make(map[string]subscriptionCheckFlags)
	}
	if nodeID != "" {
		state.checks.pending[nodeID] |= checkSingle
	} else if state.checks.sweep.Total == 0 {
		state.checks.sweep.Total = len(nodes)
		for _, node := range nodes {
			state.checks.pending[node.ID] |= checkCatalog
		}
	}
	d.subscriptions.states[sourceID] = state
	wakeSubscriptionWorker(d.subscriptions.probeWake)
	return true
}

func (c *subscriptionChecks) complete(nodeID string) {
	if c.pending[nodeID]&checkCatalog != 0 {
		c.sweep.Completed++
	}
	delete(c.pending, nodeID)
	c.finishSweep()
}

// retain discards queued work for removed nodes after a successful refresh.
func (c *subscriptionChecks) retain(nodes []subscription.Node) {
	if len(c.pending) == 0 {
		return
	}
	live := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		live[node.ID] = true
	}
	for nodeID, flags := range c.pending {
		if live[nodeID] {
			continue
		}
		delete(c.pending, nodeID)
		if flags&checkCatalog != 0 {
			c.sweep.Total--
		}
	}
	c.finishSweep()
}

func (c *subscriptionChecks) finishSweep() {
	if c.sweep.Completed == c.sweep.Total {
		c.sweep = SubscriptionCheckProgress{}
	}
	if len(c.pending) == 0 {
		c.pending = nil
	}
}

// subscriptionNodeStatus exposes observation data without returning the link or
// keeping references to health values that can change after the lock is released.
func subscriptionNodeStatus(node subscription.Node, h *health, checking bool) SubscriptionNodeStatus {
	out := SubscriptionNodeStatus{ID: node.ID, Name: node.Name, Health: subscriptionNodeHealth(h), Checking: checking}
	if h != nil && h.known {
		at := h.checked
		out.CheckedAt = &at
		if h.ok {
			latency := h.latency.Milliseconds()
			out.LatencyMS = &latency
		} else {
			out.CheckError = h.err
		}
	}
	return out
}

// subscriptionProbeTarget binds a result to the exact activated catalog. An
// isolated probe carries the saved link for a node absent from the main engine.
type subscriptionProbeTarget struct {
	tag   string
	epoch *byte
	link  string
}

func (d *Daemon) subscriptionProbeTargetsLocked(tags []string) []subscriptionProbeTarget {
	targets := make([]subscriptionProbeTarget, 0, len(tags))
	for _, tag := range tags {
		sourceID, nodeID, _ := model.ParseManagedTarget(tag)
		state := d.subscriptions.states[sourceID]
		target := subscriptionProbeTarget{tag: tag, epoch: state.probeEpoch}
		if !slices.Contains(d.subscriptions.members, tag) {
			index := slices.IndexFunc(state.snapshot.Nodes, func(node subscription.Node) bool { return node.ID == nodeID })
			if index == -1 {
				continue
			}
			target.link = state.snapshot.Nodes[index].Link
		}
		targets = append(targets, target)
	}
	return targets
}

// recordSubscriptionProbeLocked reports whether the eligible pool changed.
func (d *Daemon) recordSubscriptionProbeLocked(target subscriptionProbeTarget, result DiagnosticResult, now time.Time) bool {
	sourceID, nodeID, _ := model.ParseManagedTarget(target.tag)
	state, exists := d.subscriptions.states[sourceID]
	if !exists || target.epoch != state.probeEpoch {
		return false
	}
	h := d.health[target.tag]
	if h == nil {
		h = &health{}
		d.health[target.tag] = h
	}
	wasHealthy := h.known && h.ok
	h.record(result.OK, time.Duration(result.Latency)*time.Millisecond, result.Error, now)
	state.checks.complete(nodeID)
	d.subscriptions.states[sourceID] = state
	return wasHealthy != result.OK
}

// Reset cross-source observations before compiling a draft and publishing its pool.
func (d *Daemon) discardReplacedSubscriptionHealthLocked(previous map[string]appliedSubscription) {
	for tag := range d.health {
		source, _, managed := model.ParseManagedTarget(tag)
		if managed && subscriptionIdentity(previous[source].source) != subscriptionIdentity(d.subscriptions.states[source].source) {
			delete(d.health, tag)
		}
	}
}
