package ui

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	// The form carries each rendered rule key up to twice in URL-encoded form.
	routingFormSize = 2 << 20
	routingProvider = "provider"
	routingAll      = "all"
	routingOwn      = "own"
	ownVPNGroup     = "own-vpn"
	ownDirectGroup  = "own-direct"
)

// routingDraft holds the fields submitted for the selected mode. An absent
// list keeps the corresponding applied group.
type routingDraft struct {
	Mode        string
	VPN, Direct *routingList
	Switches    map[string]bool
	Overlap     bool
}

type routingList struct {
	Value        string
	Entries      []string
	InvalidLines []int
	ReadOnlyNote string
}

// routingState joins configured source and target choices with their latest
// applied status for both rendering and save admission.
type routingState struct {
	source        string
	sub           AppliedSubscription
	subscriptions []AppliedSubscription
	rules         RoutingRules
	class         stats.TargetClass
	health        map[string]ConnectionStatus
}

func (p pages) routingGet(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleManage && role != RoleView {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	p.renderRouting(w, r, http.StatusOK, p.deps.Config(), nil, "")
}

func (p pages) routingPost(w http.ResponseWriter, r *http.Request) {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, routingFormSize)
	if err := r.ParseForm(); err != nil {
		p.renderRouting(w, r, http.StatusBadRequest, p.deps.Config(), nil, "routing_invalid_form")
		return
	}
	cfg, message := p.checkRevision(r)
	if message != "" {
		p.renderRouting(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed")
		return
	}

	network := cfg.HomeNetwork()
	if network == nil || network.Mode == model.ModeFull {
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, nil, "")
		return
	}
	form := r.PostForm
	mode := form.Get("mode")
	state := p.routingState(cfg, network)
	providerProblem := state.providerProblem()
	keepProvider := state.keepsWithheldProvider(network, cfg.ActiveProviderRules())
	if keepProvider && !form.Has("mode") {
		mode = routingProvider
	}
	switch {
	case len(form["mode"]) > 1 || (mode != routingProvider && mode != routingAll && mode != routingOwn):
		p.renderRouting(w, r, http.StatusBadRequest, cfg, nil, "routing_invalid_mode")
		return
	case mode == routingProvider && providerProblem != "" && !keepProvider:
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, nil, providerProblem)
		return
	case mode == routingAll && !state.canUseVPN():
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, nil, state.mainProblem())
		return
	case len(form[ownVPNGroup]) > 1 || len(form[ownDirectGroup]) > 1:
		p.renderRouting(w, r, http.StatusBadRequest, cfg, nil, "routing_invalid_form")
		return
	}

	draft := routingDraft{Mode: mode}
	vpn, direct := routingOwnGroups(cfg, ownVPNGroup, network.Target), routingOwnGroups(cfg, ownDirectGroup, model.TargetDirect)
	vpnEditable, directEditable := state.canUseVPN() && !vpn.readOnly(), !direct.readOnly()
	if (form.Has(ownVPNGroup) && !vpnEditable) || (form.Has(ownDirectGroup) && !directEditable) {
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, &draft, "routing_list_read_only")
		return
	}
	if form.Has(ownVPNGroup) {
		draft.VPN = parseRoutingList(form.Get(ownVPNGroup))
	}
	if form.Has(ownDirectGroup) {
		draft.Direct = parseRoutingList(form.Get(ownDirectGroup))
	}
	var valid bool
	draft.Switches, valid = submittedRuleSwitches(form)
	if !valid || (len(draft.Switches) != 0 && cfg.ProviderRules == nil) {
		p.renderRouting(w, r, http.StatusBadRequest, cfg, &draft, "routing_invalid_form")
		return
	}
	switchesChanged := draft.changesSwitches(cfg.ProviderRules)
	if switchesChanged {
		if providerProblem == "setup_rules_withheld" {
			draft.Switches = nil
			p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, &draft, "routing_rules_changed")
			return
		}
	} else {
		// A ready form submits unchanged controls along with unrelated edits.
		draft.Switches = nil
	}
	if (draft.VPN != nil && len(draft.VPN.InvalidLines) != 0) ||
		(draft.Direct != nil && len(draft.Direct.InvalidLines) != 0) {
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, &draft, "")
		return
	}
	draft.Overlap = vpnEditable && directEditable &&
		routingListsOverlap(vpn.effectiveEntries(draft.VPN), direct.effectiveEntries(draft.Direct))
	if draft.Overlap {
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, &draft, "")
		return
	}
	draft.apply(cfg, network, state.source)

	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	revision := form.Get("rev")
	var err error
	if switchesChanged {
		err = p.deps.ApplyRuleSwitches(ctx, cfg, revision, state.source)
	} else {
		err = p.deps.Apply(ctx, cfg, revision)
	}
	if err == nil {
		redirectWithFlash(w, r, "/routing", "flash_saved")
		return
	}
	current := p.deps.Config()
	var unsaved *model.AppliedUnsavedError
	switch {
	case errors.As(err, &unsaved):
		p.renderRouting(w, r, http.StatusInternalServerError, current, nil, "apply_not_saved")
	case errors.Is(err, model.ErrConfigChanged), Revision(current) != revision:
		p.renderRouting(w, r, http.StatusConflict, current, nil, "revision_changed")
	case errors.Is(err, subscription.ErrRulesWithheld):
		draft.Switches = nil
		p.renderRouting(w, r, http.StatusUnprocessableEntity, current, &draft, "routing_rules_changed")
	default:
		p.renderRouting(w, r, http.StatusUnprocessableEntity, current, &draft, "routing_apply_error")
	}
}

// routingRulesSource prefers the saved source so switching modes retains
// its rule keys. A new rules setup uses the main subscription if available.
func routingRulesSource(cfg *model.Config, network *model.Network) string {
	if cfg.ProviderRules != nil {
		return cfg.ProviderRules.Source
	}
	if id, _, ok := model.ParseManagedTarget(network.Target); ok {
		return id
	}
	if len(cfg.Subscriptions) != 0 {
		return cfg.Subscriptions[0].ID
	}
	return ""
}

func (p pages) routingState(cfg *model.Config, network *model.Network) routingState {
	source := routingRulesSource(cfg, network)
	health := p.deps.OverviewStatus().Connections
	subs := p.deps.Subscriptions()
	return routingState{
		source: source, sub: appliedSubscriptionFor(subs, source), subscriptions: subs,
		rules: p.routingRules(cfg), class: connectionClass(network.Target, health), health: health,
	}
}

func (s routingState) canUseVPN() bool {
	return s.class == stats.TargetVPN || s.class == stats.TargetMixed
}

func (s routingState) mainProblem() string {
	switch s.class {
	case stats.TargetDirect:
		return "overview_direct_hint"
	case stats.TargetBlock:
		return "routing_main_blocked"
	default:
		return "routing_need_main"
	}
}

func (s routingState) providerProblem() string {
	switch {
	case s.sub.RulesWithheld || s.rules.State == "withheld":
		return "setup_rules_withheld"
	case s.source == "":
		return "routing_need_subscription"
	case !s.canUseVPN():
		return s.mainProblem()
	}
	return ""
}

// Keeping the saved policy does not select a currently unavailable mode.
func (s routingState) keepsWithheldProvider(network *model.Network, settings *model.ProviderRulesSettings) bool {
	return s.providerProblem() == "setup_rules_withheld" && settings != nil && network.Default == model.DefaultProfile
}

func (d routingDraft) apply(cfg *model.Config, network *model.Network, source string) {
	if d.Mode == routingProvider {
		network.Default = model.DefaultProfile
		if cfg.ProviderRules == nil {
			cfg.ProviderRules = &model.ProviderRulesSettings{Source: source}
		}
	} else {
		network.Default = model.TargetDirect
		if d.Mode == routingAll {
			network.Default = network.Target
		}
	}
	if cfg.ProviderRules != nil {
		cfg.ProviderRules.Off = d.Mode != routingProvider
		d.saveSwitches(cfg.ProviderRules)
	}
	saveRoutingList(cfg, ownVPNGroup, network.Target, d.VPN)
	saveRoutingList(cfg, ownDirectGroup, model.TargetDirect, d.Direct)
}

// changesSwitches compares submitted states with the applied revision,
// including legacy disabled keys represented by opaque controls.
func (d routingDraft) changesSwitches(settings *model.ProviderRulesSettings) bool {
	if len(d.Switches) == 0 {
		return false
	}
	disabled := settings.DisabledRuleKeys()
	for key, enabled := range d.Switches {
		wasEnabled := !disabled[key]
		if enabled != wasEnabled {
			return true
		}
	}
	return false
}

func (d routingDraft) saveSwitches(settings *model.ProviderRulesSettings) {
	if len(d.Switches) == 0 {
		return
	}
	settings.Disabled = slices.DeleteFunc(settings.Disabled, func(key string) bool {
		return d.Switches[key] || d.Switches[model.RedactedProviderRuleKey(key)]
	})
	disabled := settings.DisabledRuleKeys()
	for _, key := range slices.Sorted(maps.Keys(d.Switches)) {
		if !d.Switches[key] && !disabled[key] {
			settings.Disabled = append(settings.Disabled, key)
		}
	}
}

func parseRoutingList(value string) *routingList {
	list := &routingList{Value: value}
	lineNumber := 0
	for line := range strings.SplitSeq(value, "\n") {
		lineNumber++
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := model.ParseEntry(line)
		if err != nil {
			list.InvalidLines = append(list.InvalidLines, lineNumber)
			continue
		}
		list.Entries = append(list.Entries, entry.String())
	}
	return list
}

// ownRoutingGroups collects exact name matches. Several groups sharing a
// reserved name or one with advanced settings cannot be edited as a list.
type ownRoutingGroups struct {
	groups []*model.Group
	target string
}

func routingOwnGroups(cfg *model.Config, name, target string) ownRoutingGroups {
	result := ownRoutingGroups{target: target}
	for i := range cfg.Groups {
		group := &cfg.Groups[i]
		if group.Name == name {
			result.groups = append(result.groups, group)
		}
	}
	return result
}

func (l ownRoutingGroups) readOnly() bool {
	switch len(l.groups) {
	case 0:
		return false
	case 1:
		g := l.groups[0]
		return g.Target != l.target || g.IsGeo() || g.Disabled || g.Except ||
			len(g.DisabledEntries)+len(g.DisabledCategories)+len(g.DisabledCountries) != 0
	default:
		return true
	}
}

func (l ownRoutingGroups) effectiveEntries(draft *routingList) []string {
	if draft != nil {
		return draft.Entries
	}
	if len(l.groups) == 1 {
		return l.groups[0].Entries
	}
	var entries []string
	for _, group := range l.groups {
		entries = append(entries, group.Entries...)
	}
	return entries
}

func routingListsOverlap(vpn, direct []string) bool {
	vpnEntries := make(map[model.Entry]bool, len(vpn))
	for _, raw := range vpn {
		if entry, err := model.ParseEntry(raw); err == nil {
			vpnEntries[entry] = true
		}
	}
	for _, raw := range direct {
		if entry, err := model.ParseEntry(raw); err == nil && vpnEntries[entry] {
			return true
		}
	}
	return false
}

// saveRoutingList updates a reserved group in place so the order of the
// surrounding groups keeps its meaning for overlapping entries.
func saveRoutingList(cfg *model.Config, name, target string, list *routingList) {
	if list == nil {
		return
	}
	for i := range cfg.Groups {
		group := &cfg.Groups[i]
		if group.Name == name {
			group.Entries = list.Entries
			return
		}
	}
	if len(list.Entries) != 0 {
		cfg.Groups = append(cfg.Groups, model.Group{Name: name, Target: target, Entries: list.Entries})
	}
}

// submittedRuleSwitches accepts the rows from the rendered form. A refresh
// may remove a rule before POST without changing the config revision.
func submittedRuleSwitches(form url.Values) (map[string]bool, bool) {
	submitted := make(map[string]bool, len(form["rule"]))
	for _, key := range form["rule"] {
		if len(key) == 0 || len(key) > model.MaxProviderRuleKey {
			return nil, false
		}
		submitted[key] = false
	}
	for _, key := range form["enabled"] {
		if _, ok := submitted[key]; !ok {
			return nil, false
		}
		submitted[key] = true
	}
	return submitted, true
}
