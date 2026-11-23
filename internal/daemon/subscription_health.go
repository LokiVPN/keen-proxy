package daemon

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/sagernet/sing-box/adapter"
)

const (
	subscriptionSwitchInitial = "initial"
	subscriptionSwitchFailure = "failure"
	subscriptionSwitchRemoved = "removed"
	// subscriptionSwitchFallback marks the reserve; the selection has no node.
	subscriptionSwitchFallback  = "fallback"
	subscriptionSwitchRecovered = "recovered"
	subscriptionProbeWorkers    = 4
)

// restoreSubscriptionSelectorsLocked replays the last valid selections after
// core activation. The default block handles a removed node with no known replacement.
func (d *Daemon) restoreSubscriptionSelectorsLocked(out compile.Output, restarted bool, now time.Time) error {
	d.subscriptions.selectors, d.subscriptions.members = out.SubscriptionSelectors, out.SubscriptionOutbounds
	d.subscriptions.balances = out.SubscriptionBalances
	if restarted {
		d.subscriptions.generation++
		if len(out.SubscriptionOutbounds) > 0 {
			wakeSubscriptionWorker(d.subscriptions.probeWake)
		}
	}
	for _, selector := range d.subscriptions.selectors {
		state := d.subscriptions.states[selector.SourceID]
		selection := state.snapshot.Selection
		target, reason := model.ManagedTarget(selector.SourceID, selection.Node), selection.Reason
		if !slices.Contains(selector.Candidates, target) {
			if selection.Node == "" && reason == subscriptionSwitchFallback && selector.Fallback != "" {
				target = selector.Fallback
			} else if selection.Node != "" || reason == subscriptionSwitchRemoved {
				target, reason = d.firstHealthySubscriptionNodeLocked(selector.Candidates, now), subscriptionSwitchRemoved
				if target == model.TargetBlock && selector.Fallback != "" {
					target, reason = selector.Fallback, subscriptionSwitchFallback
				}
			} else if len(selector.Candidates) > 0 {
				target, reason = selector.Candidates[0], subscriptionSwitchInitial
			} else {
				target = model.TargetBlock
			}
		}
		if !d.eng.Select(selector.Tag, target) {
			return errors.New("could not activate subscription selector")
		}
		_, node, _ := model.ParseManagedTarget(target)
		if node != selection.Node || reason != selection.Reason {
			state.snapshot.Selection = subscriptionSelection{Node: node, At: now, Reason: reason}
		}
		onNode := node != ""
		state.unavailable = target == model.TargetBlock || (onNode && d.health[target].down(now, d.subscriptionDownAfterLocked())) || (!onNode && reason == subscriptionSwitchFallback)
		d.subscriptions.states[selector.SourceID] = state
	}
	return d.updateSubscriptionBalancesLocked()
}

// updateSubscriptionBalancesLocked publishes healthy member identities with
// the lifetime of the current source. The engine filters by transport at the
// point of routing.
func (d *Daemon) updateSubscriptionBalancesLocked() error {
	for _, balance := range d.subscriptions.balances {
		var healthy []string
		for _, tag := range balance.Candidates {
			if h := d.health[tag]; h != nil && h.known && h.ok {
				healthy = append(healthy, tag)
			}
		}
		key := subscriptionFingerprint(d.subscriptions.states[balance.SourceID].source)
		if !d.eng.UpdateSubscriptionBalance(balance.Tag, key, healthy) {
			return errors.New("could not activate subscription balance")
		}
	}
	return nil
}

// reorderSubscriptionCandidatesLocked changes only the provider-order tie breaker.
func (d *Daemon) reorderSubscriptionCandidatesLocked(id string, nodes []subscription.Node) {
	for i, selector := range d.subscriptions.selectors {
		if selector.SourceID != id {
			continue
		}
		candidates := make([]string, 0, len(nodes))
		for _, node := range nodes {
			candidates = append(candidates, model.ManagedTarget(id, node.ID))
		}
		d.subscriptions.selectors[i].Candidates = candidates
		return
	}
}

// A previous success may be too old when a large subscription is between sweeps.
func (d *Daemon) firstHealthySubscriptionNodeLocked(candidates []string, now time.Time) string {
	return d.firstSubscriptionNodeUpLocked(candidates, now, 0)
}

// firstSubscriptionNodeUpLocked also requires the success streak to last upAfter,
// so a flapping node does not pull traffic off the reserve.
func (d *Daemon) firstSubscriptionNodeUpLocked(candidates []string, now time.Time, upAfter time.Duration) string {
	f := d.cfg.Failover
	cutoff := now.Add(-(2*time.Duration(f.Interval)*time.Second + subscriptionProbeTimeout(f)))
	for _, tag := range candidates {
		if h := d.health[tag]; h != nil && h.known && h.ok && !h.checked.Before(cutoff) && now.Sub(h.since) >= upAfter {
			return tag
		}
	}
	return model.TargetBlock
}

func (d *Daemon) subscriptionDownAfterLocked() time.Duration {
	return time.Duration(d.cfg.Failover.DownAfter) * time.Second
}

// switchSubscriptionsLocked keeps a working active node, including after the
// former primary recovers. Only a verified replacement can take over a failed
// node; with none, a configured reserve takes over until a node has been up
// for failover.up_after.
func (d *Daemon) switchSubscriptionsLocked(now time.Time) {
	changed := false
	for _, selector := range d.subscriptions.selectors {
		id := selector.SourceID
		state := d.subscriptions.states[id]
		selection := state.snapshot.Selection
		onReserve := selection.Node == "" && selection.Reason == subscriptionSwitchFallback && selector.Fallback != ""
		active := model.ManagedTarget(id, selection.Node)
		reason := subscriptionSwitchFailure
		failed := d.health[active].down(now, d.subscriptionDownAfterLocked())
		if selection.Node == "" {
			reason, failed = subscriptionSwitchRemoved, true
		}
		if onReserve {
			reason = subscriptionSwitchRecovered
		}
		target := model.TargetBlock
		switch {
		case onReserve:
			target = d.firstSubscriptionNodeUpLocked(selector.Candidates, now, time.Duration(d.cfg.Failover.UpAfter)*time.Second)
		case failed:
			target = d.firstHealthySubscriptionNodeLocked(selector.Candidates, now)
		}
		unavailable := failed
		switch {
		case target != model.TargetBlock && d.eng.Select(selector.Tag, target):
			_, node, _ := model.ParseManagedTarget(target)
			state.snapshot.Selection = subscriptionSelection{At: now, Node: node, Reason: reason}
			changed, unavailable = true, false
			d.auditSubscriptionSelection(id, state.snapshot.Selection)
		case failed && !onReserve && selector.Fallback != "" && d.eng.Select(selector.Tag, selector.Fallback):
			state.snapshot.Selection = subscriptionSelection{At: now, Reason: subscriptionSwitchFallback}
			changed = true
			d.auditSubscriptionSelection(id, state.snapshot.Selection)
		}
		if unavailable && !state.unavailable {
			d.audit("watchdog", "Subscription nodes unavailable", id, "warn", "no candidate responded to the HTTPS check")
		}
		state.unavailable = unavailable
		d.subscriptions.states[id] = state
	}
	if changed && d.saveSubscriptionSnapshotsLocked(d.cfg) != nil {
		d.audit("watchdog", "Subscription selection not saved", "subscriptions", "warn", errSubscriptionSnapshot.Error())
	}
}

func (d *Daemon) auditSubscriptionSelectionsLocked(previous map[string]appliedSubscription) {
	for _, selector := range d.subscriptions.selectors {
		id := selector.SourceID
		selection := d.subscriptions.states[id].snapshot.Selection
		if !selection.At.IsZero() && previous[id].snapshot.Selection != selection {
			d.auditSubscriptionSelection(id, selection)
		}
	}
}

func (d *Daemon) auditSubscriptionSelection(id string, selection subscriptionSelection) {
	if selection.Node == "" && selection.Reason == subscriptionSwitchFallback {
		d.audit("watchdog", "Subscription reserve in use", id, "warn", "no node responded")
		return
	}
	if selection.Node == "" {
		d.audit("watchdog", "Subscription selection blocked", id, "warn", selection.Reason)
		return
	}
	d.audit("watchdog", "Subscription node selected", id, "ok", selection.Reason+" "+selection.Node)
}

// runSubscriptionHealth bounds concurrent work and publishes each completion,
// so a timed-out neighbor cannot hide a result already available to the panel.
func (d *Daemon) runSubscriptionHealth(ctx context.Context) {
	for ctx.Err() == nil {
		d.mu.Lock()
		if d.closed || d.cfg == nil {
			d.mu.Unlock()
			return
		}
		tags, wait := d.subscriptionProbeBatchLocked(time.Now())
		targets := d.subscriptionProbeTargetsLocked(tags)
		generation, failover := d.subscriptions.generation, d.cfg.Failover
		d.mu.Unlock()
		if len(targets) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-d.subscriptions.probeWake:
			case <-time.After(wait):
			}
			continue
		}

		results := d.probeSubscriptionMembers(ctx, targets, failover)
		for range targets {
			completed := <-results
			d.mu.Lock()
			if ctx.Err() == nil && !d.closed && generation == d.subscriptions.generation && failover == d.cfg.Failover {
				now := time.Now()
				if d.recordSubscriptionProbeLocked(completed.target, completed.result, now) {
					if err := d.updateSubscriptionBalancesLocked(); err != nil {
						d.log.Warn("update subscription balance", "err", err)
					}
				}
			}
			d.mu.Unlock()
		}
		// Legacy automatic selection evaluates the whole batch in provider order.
		d.mu.Lock()
		if ctx.Err() == nil && !d.closed && generation == d.subscriptions.generation && failover == d.cfg.Failover {
			d.switchSubscriptionsLocked(time.Now())
		}
		d.mu.Unlock()
	}
}

const (
	probeCandidate = iota
	probePinned
	probeRequested
	probeActive
)

type subscriptionProbe struct {
	tag      string
	checked  time.Time
	priority int
	isolated bool
}

// subscriptionProbeBatchLocked gives active nodes first use of the worker slots
// and reserves a slot for due pins and alternatives when competition is high.
// Within a priority, the oldest probe wins and provider order breaks ties.
func (d *Daemon) subscriptionProbeBatchLocked(now time.Time) ([]string, time.Duration) {
	var queued []string
	pending := make(map[string]subscriptionCheckFlags)
	for _, source := range d.cfg.Subscriptions {
		state := d.subscriptions.states[source.ID]
		if len(state.checks.pending) == 0 {
			continue
		}
		for _, node := range state.snapshot.Nodes {
			if request := state.checks.pending[node.ID]; request != 0 {
				tag := model.ManagedTarget(source.ID, node.ID)
				pending[tag] = request
				queued = append(queued, tag)
			}
		}
	}
	if len(d.subscriptions.members) == 0 && len(queued) == 0 {
		return nil, time.Hour
	}
	priority := make(map[string]int)
	markPin := func(target string) {
		if _, node, ok := model.ParseManagedTarget(target); ok && node != "auto" {
			priority[target] = probePinned
		}
	}
	for _, group := range d.cfg.Groups {
		markPin(group.Target)
	}
	for _, client := range d.cfg.Clients {
		markPin(client.Target)
	}
	for _, network := range d.cfg.Networks {
		markPin(network.Target)
	}
	for _, selector := range d.subscriptions.selectors {
		node := d.subscriptions.states[selector.SourceID].snapshot.Selection.Node
		priority[model.ManagedTarget(selector.SourceID, node)] = probeActive
	}

	interval := time.Duration(d.cfg.Failover.Interval) * time.Second
	wait := interval
	var due []subscriptionProbe
	seen := make(map[string]bool, len(d.subscriptions.members))
	visit := func(tag string, isolated bool) {
		if seen[tag] {
			return
		}
		seen[tag] = true
		var checked time.Time
		if h := d.health[tag]; h != nil {
			checked = h.checked
		}
		request := pending[tag]
		if remaining := checked.Add(interval).Sub(now); request == 0 && remaining > 0 {
			wait = min(wait, remaining)
			return
		}
		rank := priority[tag]
		if request&checkSingle != 0 {
			rank = max(rank, probeRequested)
		}
		due = append(due, subscriptionProbe{tag: tag, checked: checked, priority: rank, isolated: isolated})
	}
	for _, selector := range d.subscriptions.selectors {
		for _, tag := range selector.Candidates {
			visit(tag, false)
		}
	}
	for _, tag := range d.subscriptions.members {
		visit(tag, false)
	}
	for _, tag := range queued {
		visit(tag, true)
	}
	return d.subscriptionProbeBatch(due), wait
}

// subscriptionProbeBatch reserves work for all due priority classes within the
// four total slots. At most one profile needs a transient engine.
func (d *Daemon) subscriptionProbeBatch(due []subscriptionProbe) []string {
	slices.SortStableFunc(due, func(a, b subscriptionProbe) int {
		if a.priority != b.priority {
			return cmp.Compare(b.priority, a.priority)
		}
		return a.checked.Compare(b.checked)
	})
	isolated := ""
	for _, probe := range due {
		if probe.isolated {
			if isolated == "" {
				isolated = probe.tag
			}
			if !d.subscriptions.preferCatalogCheck || probe.priority != probeRequested {
				isolated = probe.tag
				break
			}
		}
	}
	due = slices.DeleteFunc(due, func(probe subscriptionProbe) bool { return probe.isolated && probe.tag != isolated })
	first := [probeActive + 1]int{-1, -1, -1, -1}
	extra := min(subscriptionProbeWorkers, len(due))
	for i, probe := range due {
		if first[probe.priority] == -1 {
			first[probe.priority] = i
			extra--
		}
	}
	tags := make([]string, 0, min(subscriptionProbeWorkers, len(due)))
	for i, probe := range due {
		if first[probe.priority] == i {
			tags = append(tags, probe.tag)
		} else if extra > 0 {
			tags = append(tags, probe.tag)
			extra--
		} else {
			continue
		}
		if probe.isolated {
			// The single transient-engine slot alternates when both kinds are waiting.
			d.subscriptions.preferCatalogCheck = probe.priority == probeRequested
		}
	}
	return tags
}

type completedSubscriptionProbe struct {
	target subscriptionProbeTarget
	result DiagnosticResult
}

func (d *Daemon) probeSubscriptionMembers(ctx context.Context, targets []subscriptionProbeTarget, f model.Failover) <-chan completedSubscriptionProbe {
	checkURL := diagnosticHTTPSURL
	if u, err := url.Parse(f.URL); err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil {
		checkURL = f.URL
	}
	test := diagnosticTest{kind: "https", url: checkURL}
	timeout := subscriptionProbeTimeout(f)
	results := make(chan completedSubscriptionProbe, len(targets))
	for _, target := range targets {
		go func() {
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			result := d.probeSubscriptionMember(pctx, target, test)
			results <- completedSubscriptionProbe{target: target, result: result}
		}()
	}
	return results
}

func subscriptionProbeTimeout(f model.Failover) time.Duration {
	return min(diagnosticTimeout, max(3*time.Second, time.Duration(f.Interval)*time.Second))
}

func (d *Daemon) probeSubscriptionMember(ctx context.Context, target subscriptionProbeTarget, test diagnosticTest) DiagnosticResult {
	if target.link == "" {
		if out, engineContext, ok := d.eng.Outbound(target.tag); ok {
			return probeSubscriptionOutbound(ctx, engineContext, out.DialContext, test)
		}
		return DiagnosticResult{Checked: time.Now(), Error: "subscription node is not running"}
	}
	cfg := &model.Config{Connections: []model.Connection{{ID: target.tag, Type: model.ConnLink, Link: target.link}}}
	raw, err := compile.ConnectionValidationConfig(cfg)
	var result DiagnosticResult
	if err == nil {
		err = engine.WithProbeOutbound(ctx, raw, target.tag, func(out adapter.Outbound, engineContext context.Context) {
			result = probeSubscriptionOutbound(ctx, engineContext, out.DialContext, test)
		})
	}
	if err != nil {
		return DiagnosticResult{Checked: time.Now(), Error: "subscription node test could not start"}
	}
	return result
}

func probeSubscriptionOutbound(ctx, engineContext context.Context, dial profileDial, test diagnosticTest) DiagnosticResult {
	transport := &http.Transport{
		DialContext:       diagnosticDialer(engineContext, dial),
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return diagnosticRequest(ctx, client, test)
}
