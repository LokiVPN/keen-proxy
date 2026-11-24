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
}

type routingList struct {
	Value        string
	Entries      []string
	InvalidLines []int
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

	network := homeNetwork(cfg)
	if network == nil || network.Mode == model.ModeFull {
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, nil, "")
		return
	}
	form := r.PostForm
	mode := form.Get("mode")
	source := routingRulesSource(cfg, network)
	switch {
	case len(form["mode"]) != 1 || (mode != routingProvider && mode != routingAll && mode != routingOwn):
		p.renderRouting(w, r, http.StatusBadRequest, cfg, nil, "routing_invalid_mode")
		return
	case mode == routingProvider && source == "":
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, nil, "routing_need_subscription")
		return
	case mode != routingOwn && !routingHasMain(network):
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, nil, "routing_need_main")
		return
	case len(form[ownVPNGroup]) > 1 || len(form[ownDirectGroup]) > 1:
		p.renderRouting(w, r, http.StatusBadRequest, cfg, nil, "routing_invalid_form")
		return
	}

	draft := routingDraft{Mode: mode}
	// The selected mode controls which lists the form exposes.
	if mode != routingAll && form.Has(ownVPNGroup) {
		draft.VPN = parseRoutingList(form.Get(ownVPNGroup))
	}
	if mode != routingOwn && form.Has(ownDirectGroup) {
		draft.Direct = parseRoutingList(form.Get(ownDirectGroup))
	}
	if mode == routingProvider {
		draft.Switches = p.routingRules(cfg).submittedSwitches(form)
	}
	if (draft.VPN != nil && len(draft.VPN.InvalidLines) != 0) ||
		(draft.Direct != nil && len(draft.Direct.InvalidLines) != 0) {
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, &draft, "")
		return
	}
	if draft.VPN != nil && len(draft.VPN.Entries) != 0 && !routingHasMain(network) {
		p.renderRouting(w, r, http.StatusUnprocessableEntity, cfg, &draft, "routing_need_main")
		return
	}
	draft.apply(cfg, network, source)

	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	revision := form.Get("rev")
	err := p.deps.Apply(ctx, cfg, revision)
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

func routingHasMain(network *model.Network) bool {
	return network.Target != "" && network.Target != model.TargetDirect && network.Target != model.TargetBlock
}

func (d routingDraft) apply(cfg *model.Config, network *model.Network, source string) {
	if d.Mode == routingProvider {
		network.Default = model.DefaultProfile
		if cfg.ProviderRules == nil {
			cfg.ProviderRules = &model.ProviderRulesSettings{Source: source}
		}
		cfg.ProviderRules.Off = false
		d.saveSwitches(cfg.ProviderRules)
	} else {
		network.Default = model.TargetDirect
		if d.Mode == routingAll {
			network.Default = network.Target
		}
		if cfg.ProviderRules != nil {
			cfg.ProviderRules.Off = true
		}
	}
	saveRoutingList(cfg, ownVPNGroup, network.Target, d.VPN)
	saveRoutingList(cfg, ownDirectGroup, model.TargetDirect, d.Direct)
}

func (d routingDraft) saveSwitches(settings *model.ProviderRulesSettings) {
	if len(d.Switches) == 0 {
		return
	}
	settings.Disabled = slices.DeleteFunc(settings.Disabled, func(key string) bool { return d.Switches[key] })
	for _, key := range slices.Sorted(maps.Keys(d.Switches)) {
		if !d.Switches[key] && !slices.Contains(settings.Disabled, key) {
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
			if target != "" {
				group.Target = target
			}
			return
		}
	}
	if len(list.Entries) != 0 {
		cfg.Groups = append(cfg.Groups, model.Group{Name: name, Target: target, Entries: list.Entries})
	}
}

// submittedSwitches intersects the posted rows and the current available
// rules. A concurrent subscription refresh can add, remove or invalidate
// rows without changing the applied config revision.
func (rules RoutingRules) submittedSwitches(form url.Values) map[string]bool {
	if rules.State != "ready" && rules.State != "partial" {
		return nil
	}
	submitted := make(map[string]bool, len(form["rule"]))
	for _, key := range form["rule"] {
		submitted[key] = false
	}
	for _, key := range form["enabled"] {
		if _, ok := submitted[key]; ok {
			submitted[key] = true
		}
	}
	changes := map[string]bool{}
	for _, rule := range rules.Rules {
		if on, ok := submitted[rule.Key]; ok && rule.switchable() {
			changes[rule.Key] = on
		}
	}
	return changes
}
