package daemon

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	subscriptionPending         = "pending"
	subscriptionActivationError = "activation_error"
	subscriptionPreviewTTL      = 5 * time.Minute
	subscriptionPreviewLimit    = 4
	subscriptionRefreshDefault  = 12 * time.Hour
)

// SubscriptionNodeStatus displays opaque node identity and observed health.
type SubscriptionNodeStatus struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Health     string     `json:"health"`
	Checking   bool       `json:"checking,omitempty"`
	CheckedAt  *time.Time `json:"checked_at,omitempty"`
	LatencyMS  *int64     `json:"latency_ms,omitempty"`
	CheckError string     `json:"check_error,omitempty"`
}

// SubscriptionStatus is the public view of one preview or applied source.
// Download settings, device identity, and connection credentials stay private.
type SubscriptionStatus struct {
	ID              string                     `json:"id"`
	State           string                     `json:"state"`
	Metadata        subscription.Metadata      `json:"metadata"`
	Nodes           []SubscriptionNodeStatus   `json:"nodes"`
	Skipped         int                        `json:"skipped,omitempty"`
	Error           string                     `json:"error,omitempty"`
	LastAttempt     *time.Time                 `json:"last_attempt,omitempty"`
	LastSuccess     *time.Time                 `json:"last_success,omitempty"`
	ActiveNode      string                     `json:"active_node,omitempty"`
	LastSwitch      *time.Time                 `json:"last_switch,omitempty"`
	SwitchReason    string                     `json:"switch_reason,omitempty"`
	Unavailable     bool                       `json:"unavailable,omitempty"`
	CheckProgress   *SubscriptionCheckProgress `json:"check_progress,omitempty"`
	BalanceEligible *int                       `json:"balance_eligible,omitempty"`
	// Fallback echoes the configured reserve used while no node answers.
	Fallback string `json:"fallback,omitempty"`
	// RulesError tells why the latest provider-rules update of the configured
	// source failed, as a fixed English message.
	RulesError string `json:"rules_error,omitempty"`
	// RulesState is the provider-rules state of the configured source, as
	// ProviderRules reports it; empty for other sources.
	RulesState ProviderRulesState `json:"rules_state,omitempty"`
}

// subscriptionRuntime separates downloads from the state committed under d.mu.
type subscriptionRuntime struct {
	directory          string
	fetcher            *subscription.Fetcher
	slot               chan struct{}
	wake               chan struct{}
	probeWake          chan struct{}
	preferCatalogCheck bool

	// geoDestination tells whether a geo file download may connect to an
	// address: publicDestination, which tests serving geo files on loopback
	// replace.
	geoDestination func(netip.AddrPort) bool

	states     map[string]appliedSubscription
	previews   map[subscription.Source]subscriptionAttempt
	selectors  []compile.SubscriptionSelector
	balances   []compile.SubscriptionBalance
	members    []string
	generation uint64
	savedPath  string
}

type appliedSubscription struct {
	source      subscription.Source
	snapshot    subscriptionSnapshot
	attempt     subscriptionAttempt
	next        time.Time
	failures    int
	request     *subscriptionRefresh
	unavailable bool
	checks      subscriptionChecks
	// A probe started against an older catalog can finish after a refresh or
	// Apply, including when the core stayed in place.
	probeEpoch *byte
	// rulesRetry is when the worker downloads the geo files that partial
	// provider rules lack; rulesFailures counts the retries for backoff.
	rulesRetry    time.Time
	rulesFailures int
}

type subscriptionAttempt struct {
	result subscription.Result
	at     time.Time
	// rules is the provider-rules state built from result for the configured
	// source; nil when this attempt did not evaluate rules.
	rules *rulesSnapshot
}

// subscriptionRefresh identifies one in-flight download even if an Apply
// removes and re-adds the same source settings before the request returns.
type subscriptionRefresh struct {
	source subscription.Source
	// rules asks the download to evaluate provider rules from previous;
	// rulesOnly downloads only the geo files that previous lacks.
	rules, rulesOnly bool
	previous         *rulesSnapshot
}

func newSubscriptionRuntime(ruleSetDir string) subscriptionRuntime {
	dir := filepath.Join(filepath.Dir(ruleSetDir), "subscriptions")
	return subscriptionRuntime{
		directory: dir,
		fetcher:   subscription.NewFetcher(filepath.Join(dir, "identity"), nil),
		slot:      make(chan struct{}, 1),
		wake:      make(chan struct{}, 1),
		probeWake: make(chan struct{}, 1),
		previews:  make(map[subscription.Source]subscriptionAttempt),

		geoDestination: publicDestination,
	}
}

// PreviewSubscription validates provider data against the running build and
// caches usable previews for Apply. It never modifies applied sources.
func (d *Daemon) PreviewSubscription(ctx context.Context, source subscription.Source) SubscriptionStatus {
	attempt := d.fetchSubscription(ctx, source)
	if attempt.result.State == subscription.StateReady {
		d.mu.Lock()
		d.expireSubscriptionPreviewsLocked(attempt.at)
		var oldest subscription.Source
		var first time.Time
		for key, preview := range d.subscriptions.previews {
			if first.IsZero() || preview.at.Before(first) {
				oldest, first = key, preview.at
			}
		}
		if _, exists := d.subscriptions.previews[subscriptionIdentity(source)]; !exists && len(d.subscriptions.previews) >= subscriptionPreviewLimit {
			delete(d.subscriptions.previews, oldest)
		}
		d.subscriptions.previews[subscriptionIdentity(source)] = attempt
		d.mu.Unlock()
	}
	status := SubscriptionStatus{
		ID: source.ID, State: attempt.result.State, Metadata: subscriptionMetadata(attempt.result.Metadata),
		Nodes: make([]SubscriptionNodeStatus, 0, len(attempt.result.Nodes)), Error: attempt.result.Error,
		Skipped: attempt.result.Skipped, LastAttempt: &attempt.at,
	}
	for _, node := range attempt.result.Nodes {
		status.Nodes = append(status.Nodes, SubscriptionNodeStatus{ID: node.ID, Name: node.Name, Health: "unknown"})
	}
	return status
}

// Subscriptions reports applied sources in configuration order.
func (d *Daemon) Subscriptions() []SubscriptionStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]SubscriptionStatus, 0, len(d.subscriptions.states))
	if d.cfg == nil {
		return out
	}
	for _, source := range d.cfg.Subscriptions {
		state := d.subscriptions.states[source.ID]
		snapshot, latest := state.snapshot, state.attempt
		status := SubscriptionStatus{
			ID: source.ID, State: subscriptionPending, Metadata: subscriptionMetadata(snapshot.Metadata),
			Nodes: make([]SubscriptionNodeStatus, 0, len(snapshot.Nodes)), Skipped: snapshot.Skipped,
			Unavailable: len(snapshot.Nodes) == 0, Fallback: source.Fallback,
		}
		if !latest.at.IsZero() {
			status.State, status.Error, status.LastAttempt = latest.result.State, latest.result.Error, &latest.at
			if latest.result.Metadata != (subscription.Metadata{}) {
				status.Metadata = subscriptionMetadata(latest.result.Metadata)
			}
			if latest.result.Skipped != 0 {
				status.Skipped = latest.result.Skipped
			}
		}
		if !snapshot.LastSuccess.IsZero() {
			status.LastSuccess = &snapshot.LastSuccess
		}
		if snapshot.Rules != nil {
			status.RulesError = snapshot.Rules.Error
		}
		if source.ID == providerRulesSource(d.cfg) {
			status.RulesState = snapshot.Rules.state()
			if status.RulesState == ProviderRulesFailed && status.RulesError == "" {
				status.RulesError = "No provider rules are available"
			}
		}
		if !snapshot.Selection.At.IsZero() {
			status.LastSwitch = &snapshot.Selection.At
			status.SwitchReason = snapshot.Selection.Reason
		}
		if slices.ContainsFunc(d.subscriptions.selectors, func(selector compile.SubscriptionSelector) bool {
			return selector.SourceID == source.ID
		}) {
			status.ActiveNode = snapshot.Selection.Node
			status.Unavailable = status.Unavailable || state.unavailable
		}
		if state.checks.sweep.Total != 0 {
			progress := state.checks.sweep
			status.CheckProgress = &progress
		}
		eligible := 0
		for _, node := range snapshot.Nodes {
			h := d.health[model.ManagedTarget(source.ID, node.ID)]
			status.Nodes = append(status.Nodes, subscriptionNodeStatus(node, h, state.checks.pending[node.ID] != 0))
			if h != nil && h.known && h.ok {
				eligible++
			}
		}
		if slices.ContainsFunc(d.subscriptions.balances, func(balance compile.SubscriptionBalance) bool {
			return balance.SourceID == source.ID
		}) {
			status.BalanceEligible = &eligible
		}
		out = append(out, status)
	}
	return out
}

func subscriptionMetadata(metadata subscription.Metadata) subscription.Metadata {
	if metadata.Usage != nil {
		usage := *metadata.Usage
		metadata.Usage = &usage
	}
	return metadata
}

func subscriptionNodeHealth(h *health) string {
	switch {
	case h == nil || !h.known:
		return "unknown"
	case h.ok:
		return "available"
	default:
		return "unavailable"
	}
}

// RefreshSubscription asks the download worker to check a saved source now.
// Requests for the same source coalesce while a download is in flight.
func (d *Daemon) RefreshSubscription(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, exists := d.subscriptions.states[id]
	if !exists || d.closed {
		return false
	}
	// A geo file retry in flight does not fetch the subscription.
	if state.request == nil || state.request.rulesOnly {
		state.next = time.Time{}
		d.subscriptions.states[id] = state
		wakeSubscriptionWorker(d.subscriptions.wake)
	}
	return true
}

func wakeSubscriptionWorker(wake chan struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (d *Daemon) expireSubscriptionPreviewsLocked(now time.Time) {
	for source, preview := range d.subscriptions.previews {
		if now.Sub(preview.at) >= subscriptionPreviewTTL {
			delete(d.subscriptions.previews, source)
		}
	}
}

// applyWithSubscriptions obtains missing candidates, and the provider rules of
// a new candidate for the configured source, outside the Apply lock and
// rechecks them against the configuration that is active when Apply acquires it.
func (d *Daemon) applyWithSubscriptions(ctx context.Context, cfg *model.Config) error {
	candidates := make(map[subscription.Source]subscriptionAttempt)
	for {
		d.mu.Lock()
		if err := d.applyAdmissionLocked(ctx); err != nil {
			d.mu.Unlock()
			return err
		}
		d.expireSubscriptionPreviewsLocked(time.Now())
		source, missing := d.missingSubscriptionLocked(cfg, candidates)
		if !missing {
			identity, pending := d.pendingProviderRulesLocked(cfg, candidates)
			if !pending {
				err := d.applyConfigLocked(ctx, cfg, true, candidates)
				d.mu.Unlock()
				return err
			}
			d.mu.Unlock()
			candidate := candidates[identity]
			geoCtx, cancel := applyGeoContext(ctx)
			candidate.rules = d.evaluateProviderRules(geoCtx, candidate.result, nil)
			cancel()
			candidates[identity] = candidate
			continue
		}
		d.mu.Unlock()
		attempt := d.fetchSubscription(ctx, source)
		if attempt.result.State != subscription.StateReady {
			message := attempt.result.Error
			if message == "" {
				message = "no usable subscription nodes"
			}
			err := fmt.Errorf("subscription %q: %s", source.ID, message)
			by, from := applyActor(ctx)
			d.audit(by, "Configuration rejected", "config", "error", err.Error()+from)
			return err
		}
		candidates[subscriptionIdentity(source)] = attempt
	}
}

func (d *Daemon) missingSubscriptionLocked(cfg *model.Config, candidates map[subscription.Source]subscriptionAttempt) (subscription.Source, bool) {
	for _, source := range cfg.Subscriptions {
		identity := subscriptionIdentity(source)
		if subscriptionIdentity(d.subscriptions.states[source.ID].source) == identity {
			continue
		}
		if _, exists := candidates[identity]; !exists {
			if preview, ok := d.subscriptions.previews[identity]; ok {
				candidates[identity] = preview
			} else {
				return source, true
			}
		}
	}
	return subscription.Source{}, false
}

// pendingProviderRulesLocked finds the candidate of the configured rules source
// whose rules this Apply has not evaluated yet. A source kept from the running
// configuration is left to the refresh worker.
func (d *Daemon) pendingProviderRulesLocked(cfg *model.Config, candidates map[subscription.Source]subscriptionAttempt) (subscription.Source, bool) {
	id := providerRulesSource(cfg)
	for _, source := range cfg.Subscriptions {
		identity := subscriptionIdentity(source)
		if source.ID != id || subscriptionIdentity(d.subscriptions.states[id].source) == identity {
			continue
		}
		if candidate, ok := candidates[identity]; ok && candidate.rules == nil {
			return identity, true
		}
	}
	return subscription.Source{}, false
}

func (d *Daemon) subscriptionDraftLocked(cfg *model.Config, candidates map[subscription.Source]subscriptionAttempt) map[string]appliedSubscription {
	if len(cfg.Subscriptions) == 0 {
		return nil
	}
	states := make(map[string]appliedSubscription, len(cfg.Subscriptions))
	for _, source := range cfg.Subscriptions {
		previous := d.subscriptions.states[source.ID]
		if subscriptionIdentity(previous.source) == subscriptionIdentity(source) {
			previous.source = source // a reserve edit keeps nodes, health and selection
			syncProviderRules(cfg, &previous)
			states[source.ID] = previous
			continue
		}
		state := appliedSubscription{source: source}
		state.snapshot.Selection = previous.snapshot.Selection
		if candidate, ok := candidates[subscriptionIdentity(source)]; ok {
			state.recordAttempt(candidate)
			state.accept(candidate)
		}
		syncProviderRules(cfg, &state)
		state.scheduleRulesRetry(time.Now())
		states[source.ID] = state
	}
	return states
}

// fetchSubscription serializes direct downloads and bounds concurrent validation.
func (d *Daemon) fetchSubscription(ctx context.Context, source subscription.Source) subscriptionAttempt {
	select {
	case d.subscriptions.slot <- struct{}{}:
	case <-ctx.Done():
		return subscriptionAttempt{result: subscription.Result{State: subscription.StateNetworkError, Error: "subscription fetch cancelled", Transient: true}, at: time.Now()}
	}
	defer func() { <-d.subscriptions.slot }()
	result := d.subscriptions.fetcher.Fetch(ctx, source)
	if result.State == subscription.StateReady {
		var skipped int
		result.Nodes, skipped = supportedSubscriptionNodes(ctx, result.Nodes)
		result.Skipped += skipped
		if len(result.Nodes) == 0 {
			result.State, result.Error = subscription.StateUnsupported, "no subscription nodes are supported by this build"
		}
	}
	return subscriptionAttempt{result: result, at: time.Now()}
}

// supportedSubscriptionNodes validates the common case in one engine instance.
// A mixed list can still use supported nodes on builds with a smaller registry.
func supportedSubscriptionNodes(ctx context.Context, nodes []subscription.Node) ([]subscription.Node, int) {
	if len(nodes) == 0 || validSubscriptionNodes(ctx, nodes) {
		return nodes, 0
	}
	accepted := make([]subscription.Node, 0, len(nodes))
	for i, node := range nodes {
		if ctx.Err() == nil && validSubscriptionNodes(ctx, nodes[i:i+1]) {
			accepted = append(accepted, node)
		}
	}
	return accepted, len(nodes) - len(accepted)
}

func validSubscriptionNodes(ctx context.Context, nodes []subscription.Node) bool {
	cfg := &model.Config{Connections: make([]model.Connection, 0, len(nodes))}
	for _, node := range nodes {
		_, _, valid := model.ParseManagedTarget(model.ManagedTarget("source", node.ID))
		if !valid || node.ID == "auto" {
			return false
		}
		cfg.Connections = append(cfg.Connections, model.Connection{ID: node.ID, Type: model.ConnLink, Link: node.Link})
	}
	raw, err := compile.ConnectionValidationConfig(cfg)
	return err == nil && engine.Validate(ctx, raw) == nil
}

// runSubscriptions owns scheduled downloads. Only activation and status updates
// take d.mu, so a slow provider cannot hold up configuration or interception.
func (d *Daemon) runSubscriptions(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for ctx.Err() == nil {
		d.mu.Lock()
		now := time.Now()
		d.expireSubscriptionPreviewsLocked(now)
		request := d.nextSubscriptionRefreshLocked(now)
		d.mu.Unlock()
		if request != nil {
			d.runSubscriptionRequest(ctx, request)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-d.subscriptions.wake:
		case <-tick.C:
		}
	}
}

// runSubscriptionRequest performs one claimed request: downloads run without
// d.mu and the result is committed under it.
func (d *Daemon) runSubscriptionRequest(ctx context.Context, request *subscriptionRefresh) {
	if request.rulesOnly {
		rules := d.evaluateProviderRules(ctx, subscription.Result{Routing: request.previous.Profile}, request.previous)
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.applyAdmissionLocked(ctx) == nil {
			d.finishProviderRulesRetryLocked(request, rules)
		}
		return
	}
	attempt := d.fetchSubscription(ctx, request.source)
	if request.rules && attempt.result.State == subscription.StateReady {
		attempt.rules = d.evaluateProviderRules(ctx, attempt.result, request.previous)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.applyAdmissionLocked(ctx) == nil {
		d.finishSubscriptionRefreshLocked(request, attempt)
	}
}

// nextSubscriptionRefreshLocked claims the first due request: a scheduled
// refresh, or a geo file retry for partial provider rules.
func (d *Daemon) nextSubscriptionRefreshLocked(now time.Time) *subscriptionRefresh {
	if d.cfg == nil || d.closed || d.startupBlocked != nil {
		return nil
	}
	for _, source := range d.cfg.Subscriptions {
		state := d.subscriptions.states[source.ID]
		if state.request != nil {
			continue
		}
		rulesSource := source.ID == providerRulesSource(d.cfg)
		var request *subscriptionRefresh
		switch {
		case !now.Before(state.next):
			request = &subscriptionRefresh{source: source}
			if rulesSource {
				request.rules, request.previous = true, state.snapshot.Rules
			}
		case rulesSource && state.snapshot.Rules.retryable() && !now.Before(state.rulesRetry):
			request = &subscriptionRefresh{source: source, rulesOnly: true, previous: state.snapshot.Rules}
		default:
			continue
		}
		state.request = request
		d.subscriptions.states[source.ID] = state
		return request
	}
	return nil
}

func (d *Daemon) finishSubscriptionRefreshLocked(request *subscriptionRefresh, attempt subscriptionAttempt) {
	id := request.source.ID
	previous := d.subscriptions.states[id]
	if previous.request != request {
		return
	}
	state := previous
	state.request = nil
	state.recordAttempt(attempt)
	if attempt.result.State != subscription.StateReady {
		d.subscriptions.states[id] = state
		if state.failures <= 1 {
			d.audit("system", "Subscription refresh failed", id, "warn", state.attempt.result.State)
		}
		return
	}

	state.accept(attempt)
	// Apply may have turned provider rules off or on during the download.
	syncProviderRules(d.cfg, &state)
	if attempt.rules != nil {
		state.scheduleRulesRetry(time.Now())
	}
	sameNodes := previous.probeEpoch == state.probeEpoch
	// Rule changes reach the core through the same path as node changes.
	coreChanged := !sameNodes || !sameProviderRules(previous.snapshot.Rules, state.snapshot.Rules)
	before, err := d.activateSubscriptionStateLocked(id, state, coreChanged)
	if err != nil {
		state = d.subscriptions.states[id]
		state.request = nil
		state.recordAttempt(subscriptionAttempt{at: attempt.at, result: subscription.Result{
			State: subscriptionActivationError, Error: "subscription update could not be activated or saved",
		}})
		d.subscriptions.states[id] = state
		d.audit("system", "Subscription refresh failed", id, "warn", subscriptionActivationError)
		return
	}
	if sameNodes {
		d.reorderSubscriptionCandidatesLocked(id, state.snapshot.Nodes)
	} else {
		state = d.subscriptions.states[id]
		state.checks.retain(state.snapshot.Nodes)
		d.subscriptions.states[id] = state
		d.stats.RetainSubscriptionNodes(d.subscriptions.members)
		wakeSubscriptionWorker(d.subscriptions.probeWake)
	}
	d.auditSubscriptionSelectionsLocked(before)
	d.audit("system", "Subscription refreshed", id, "ok", fmt.Sprintf("%d usable nodes", len(state.snapshot.Nodes)))
}

// activateSubscriptionStateLocked publishes state for id, reconciles the core
// when coreChanged and saves the snapshots. On failure it restores the
// previous states, health and balance sessions and returns the error; before
// holds the states as they were.
func (d *Daemon) activateSubscriptionStateLocked(id string, state appliedSubscription, coreChanged bool) (before map[string]appliedSubscription, err error) {
	before = maps.Clone(d.subscriptions.states)
	previousHealth := maps.Clone(d.health)
	d.subscriptions.states[id] = state
	var restoreBalanceSessions func()
	if coreChanged {
		restoreBalanceSessions = d.eng.SubscriptionBalanceCheckpoint()
		err = d.applySubscriptionCoreLocked()
	}
	if err == nil {
		err = d.saveSubscriptionSnapshotsLocked(d.cfg)
	}
	if err != nil {
		d.subscriptions.states = before
		d.health = previousHealth
		if coreChanged {
			restoreBalanceSessions()
			if rollback := d.applySubscriptionCoreLocked(); rollback != nil {
				d.audit("system", "Subscription rollback failed", id, "error", "previous subscription runtime could not be restored")
			}
		}
	} else if coreChanged {
		d.commitDomainCacheLocked()
	}
	return before, err
}

// applySubscriptionCoreLocked reconciles the core with the subscription
// state. Managed nodes do not change firewall exemptions or DNS, but provider
// rules live in rule-set files, which are written before the core reads them.
func (d *Daemon) applySubscriptionCoreLocked() error {
	out, err := d.compileLocked()
	if err != nil {
		return err
	}
	d.warnDroppedProviderEntries(out)
	_, err = d.applyCoreLocked(out)
	return err
}

// Canonical node identity covers all dial settings, so a reorder or display
// change has no effect on compiled configuration or active connections.
func equalSubscriptionNodes(a, b []subscription.Node) bool {
	if len(a) != len(b) {
		return false
	}
	ids := make(map[string]bool, len(a))
	for _, node := range a {
		ids[node.ID] = true
	}
	for _, node := range b {
		if !ids[node.ID] {
			return false
		}
	}
	return true
}

func (s *appliedSubscription) recordAttempt(attempt subscriptionAttempt) {
	attempt.result.Nodes, attempt.rules = nil, nil
	s.attempt = attempt
	interval := subscriptionRefreshInterval(attempt.result.Metadata)
	if attempt.result.Metadata.UpdateIntervalHours == 0 {
		interval = subscriptionRefreshInterval(s.snapshot.Metadata)
	}
	switch attempt.result.State {
	case subscription.StateNetworkError, subscriptionActivationError:
		s.failures = min(s.failures+1, 10)
		interval = min(interval, time.Minute<<(s.failures-1))
	default:
		s.failures = 0
	}
	s.next = attempt.at.Add(interval)
}

func (s *appliedSubscription) accept(attempt subscriptionAttempt) {
	result := attempt.result
	if s.probeEpoch == nil || !equalSubscriptionNodes(s.snapshot.Nodes, result.Nodes) {
		s.probeEpoch = new(byte)
	}
	s.snapshot.Nodes = result.Nodes
	s.snapshot.Metadata = result.Metadata
	s.snapshot.Skipped = result.Skipped
	s.snapshot.LastSuccess = attempt.at
	if attempt.rules != nil {
		s.snapshot.Rules = attempt.rules
	}
	s.next = attempt.at.Add(subscriptionRefreshInterval(result.Metadata))
}

// sameProviderRules compares the rules in use, ignoring download records and
// failures that do not change routing.
func sameProviderRules(a, b *rulesSnapshot) bool {
	var x, y *compile.ProviderRules
	if a != nil {
		x = a.Built
	}
	if b != nil {
		y = b.Built
	}
	return reflect.DeepEqual(x, y)
}

func subscriptionRefreshInterval(metadata subscription.Metadata) time.Duration {
	if metadata.UpdateIntervalHours == 0 {
		return subscriptionRefreshDefault
	}
	return time.Duration(max(1, min(metadata.UpdateIntervalHours, 168))) * time.Hour
}

func (d *Daemon) subscriptionCompileInputLocked() map[string][]subscription.Node {
	if len(d.subscriptions.states) == 0 {
		return nil
	}
	out := make(map[string][]subscription.Node, len(d.subscriptions.states))
	for id, state := range d.subscriptions.states {
		out[id] = state.snapshot.Nodes
	}
	return out
}

var errSubscriptionSnapshot = errors.New("subscription snapshot could not be saved")
