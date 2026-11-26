package ui

import (
	"cmp"
	"fmt"
	"net/http"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

type routingPage struct {
	Revision, Mode, Source           string
	Sources                          []connectionOption
	Draft                            bool
	Unavailable, CustomMode          string
	CanProvider, CanAll, OtherGroups bool
	VPN, Direct                      *routingList
	ProviderMode, ProviderHeading    string
	ProviderHint, AllMode, AllHint   string
	OwnHint, VPNTitle                string
	RuleState, SubscriptionUpdated   string
	Unmatched                        string
	RuleGroups                       []routingRuleGroup
	HasSwitches, Overlap             bool
}

type routingRuleGroup struct {
	Label string
	Rules []routingRuleRow
}

type routingRuleRow struct {
	Key, Label, Reason string
	Checked            bool
}

func (p pages) renderRouting(w http.ResponseWriter, r *http.Request, status int, cfg *model.Config, draft *routingDraft, messageKey string) {
	if cfg == nil {
		if status == http.StatusOK {
			status, messageKey = http.StatusServiceUnavailable, "setup_unavailable"
		}
		p.renderPage(w, r, status, "KeenProxy", messageKey)
		return
	}
	data := p.opts.pageData(r)
	data.Title, data.SignedIn = "KeenProxy", true
	data.ViewOnly = p.role(r) == RoleView
	data.Flash, data.Message = takeFlash(w, r, data.Text), data.Text[messageKey]
	data.Routing = p.routingView(cfg, draft, data.Text)
	render(w, r, status, "routing", data)
}

func (p pages) routingView(cfg *model.Config, draft *routingDraft, text map[string]string) *routingPage {
	page := routingPage{Revision: Revision(cfg)}
	network := cfg.HomeNetwork()
	if network == nil {
		page.Unavailable = text["overview_no_home"]
		return &page
	}
	if network.Mode == model.ModeFull {
		page.Unavailable = text["routing_full_policy"]
		return &page
	}
	settings := cfg.ActiveProviderRules()
	page.Source = routingRulesSource(cfg, network)
	if draft != nil {
		page.Source, page.Draft = draft.Source, true
	}
	state := p.routingState(cfg, network, page.Source)
	titles := subscriptionTitlesFor(cfg, state.subscriptions)
	for _, source := range cfg.Subscriptions {
		page.Sources = append(page.Sources, connectionOption{Target: source.ID, Label: titles.label(source.ID, text)})
	}
	page.CanAll = state.canUseVPN()
	page.Mode = routingMode(network, settings, page.CanAll)
	if page.Mode == "" {
		page.CustomMode = text["routing_custom_mode"]
	}
	providerProblem := state.providerProblem()
	keepsProvider := retainsProviderMode(network, settings, page.Source)
	page.CanProvider = providerProblem == ""
	if keepsProvider && state.withholdsRules() {
		page.Mode, page.CustomMode = routingProvider, ""
	}
	page.ProviderHint = text[cmp.Or(providerProblem, "routing_provider_hint")]
	page.ProviderMode, page.ProviderHeading = text["routing_mode_provider"], text["routing_provider_rules"]
	if state.sub.ID != "" {
		name := titles.label(state.sub.ID, text)
		page.ProviderMode = fmt.Sprintf(text["routing_mode_named_provider"], name)
		page.ProviderHeading = fmt.Sprintf(text["routing_named_provider_rules"], name)
	}
	if !state.sub.LastSuccess.IsZero() {
		page.SubscriptionUpdated = fmt.Sprintf(text["routing_subscription_updated"], overviewTimestamp(state.sub.LastSuccess, text))
	}
	page.AllMode, page.AllHint = text["overview_route_all"], text["routing_all_hint"]
	page.OwnHint, page.VPNTitle = text["routing_own_hint"], text["routing_own_vpn"]
	vpn, direct := routingOwnGroups(cfg, ownVPNGroup, network.Target), routingOwnGroups(cfg, ownDirectGroup, model.TargetDirect)
	page.OtherGroups = len(cfg.Groups) > len(vpn.groups)+len(direct.groups)
	page.VPN, page.Direct = vpn.field(text), direct.field(text)
	if !page.CanAll {
		page.AllMode, page.AllHint = text["routing_main_mode"], text[state.mainProblem()]
		page.OwnHint, page.VPNTitle = text["routing_own_direct_hint"], text["routing_own_via_main"]
		page.VPN.ReadOnlyNote = cmp.Or(page.VPN.ReadOnlyNote, page.AllHint)
	} else if state.class == stats.TargetMixed {
		selection := selectedConnection(cfg, network.Target, state.subscriptions, titles, state.health, text)
		page.AllMode = text["routing_main_mode"]
		if selection.Name != "" {
			page.AllMode = fmt.Sprintf(text["overview_follow_connection"], selection.Name)
		}
		active := state.health[network.Target]
		switch {
		case selection.ReserveDirect || active.Active == model.TargetDirect || active.ActiveClass == stats.TargetDirect:
			page.AllHint = text["overview_direct_reserve"] + " " + page.AllHint
		case selection.Reserve != "":
			page.AllHint = fmt.Sprintf(text["overview_using_reserve"], selection.Reserve) + " " + page.AllHint
		case active.Active != "" && active.Active != network.Target:
			if name := connectionName(cfg, active.Active); name != "" && active.ActiveClass != stats.TargetBlock {
				page.AllHint = fmt.Sprintf(text["overview_using_reserve"], name) + " " + page.AllHint
			}
		}
		page.OwnHint, page.VPNTitle = text["routing_own_direct_hint"], text["routing_own_via_main"]
	}
	if draft != nil {
		page.Mode = draft.Mode
		if page.Mode == routingProvider && !page.CanProvider && !keepsProvider {
			page.Mode = ""
		}
		page.Overlap = draft.Overlap
		if draft.VPN != nil {
			page.VPN = draft.VPN
		}
		if draft.Direct != nil {
			page.Direct = draft.Direct
		}
	}
	page.setRules(state, settings, draft, text)
	return &page
}

func (l ownRoutingGroups) field(text map[string]string) *routingList {
	field := &routingList{Value: strings.Join(l.effectiveEntries(nil), "\n")}
	if l.readOnly() {
		field.ReadOnlyNote = text["routing_custom_group"]
	}
	return field
}

// routingMode recognizes the defaults written by this page. A custom
// configuration is left unselected until an administrator chooses a mode.
func routingMode(network *model.Network, settings *model.ProviderRulesSettings, canUseVPN bool) string {
	switch {
	case settings != nil && network.Default == model.DefaultProfile && canUseVPN:
		return routingProvider
	case settings != nil:
		return ""
	case network.Default == "" || network.Default == model.TargetDirect:
		return routingOwn
	case network.Default == network.Target && canUseVPN:
		return routingAll
	}
	return ""
}

func (p pages) appliedRoutingRules(source string) RoutingRules {
	rules := p.deps.ProviderRules()
	if rules.Source != source {
		return RoutingRules{State: "pending"}
	}
	return rules
}

func (p *routingPage) setRules(state routingState, settings *model.ProviderRulesSettings, draft *routingDraft, text map[string]string) {
	rules := state.rules
	p.RuleState = providerRulesNotice(rules.State, text)
	if rules.State == "off" {
		p.RuleState = text["routing_rules_on_save"]
	}
	if rules.HasProfile {
		p.Unmatched = text["routing_rest_direct"]
		if rules.GlobalProxy {
			p.Unmatched = text["routing_rest_vpn"]
			switch state.class {
			case stats.TargetDirect:
				p.Unmatched = text["routing_rest_direct"]
			case stats.TargetBlock:
				p.Unmatched = text["routing_rest_blocked"]
			case stats.TargetUnknown, stats.TargetMixed:
				p.Unmatched = text["routing_rest_main"]
			}
		}
	}
	disabled := settings.DisabledRuleKeys()
	for _, action := range []string{"proxy", "direct", "block"} {
		group := routingRuleGroup{Label: text["routing_action_"+action]}
		if action == "proxy" && state.class != stats.TargetVPN {
			group.Label = text["routing_main_mode"]
		}
		for _, rule := range rules.Rules {
			if rule.Action != action || rule.private() {
				continue
			}
			row := routingRuleRow{Key: rule.Key, Label: rule.label(text), Checked: !disabled[rule.Key]}
			if rule.switchable() {
				p.HasSwitches = true
			} else {
				row.Reason = rule.reason(text)
			}
			if draft != nil {
				if checked, ok := draft.Switches[rule.Key]; ok {
					row.Checked = checked
				}
			}
			group.Rules = append(group.Rules, row)
		}
		if len(group.Rules) != 0 {
			p.RuleGroups = append(p.RuleGroups, group)
		}
	}
}

// providerRulesNotice is shared by the routing and subscription catalog views.
func providerRulesNotice(state string, text map[string]string) string {
	switch state {
	case "pending":
		return text["setup_rules_pending"]
	case "withheld":
		return text["setup_rules_withheld"]
	case "failed":
		return text["overview_rules_failed"]
	case "partial":
		return text["routing_rules_partial"]
	default:
		return ""
	}
}

func (r RoutingRule) switchable() bool {
	return r.Key != "" && r.Unavailable == ""
}

func (r RoutingRule) private() bool {
	_, category, _ := strings.Cut(r.Source, ":")
	name, _, _ := strings.Cut(category, "@")
	return strings.EqualFold(name, "private")
}

func (r RoutingRule) label(text map[string]string) string {
	if r.Source == "literals" {
		key := "routing_literal_sites"
		if r.Kind == "ip" {
			key = "routing_literal_ips"
		}
		return fmt.Sprintf(text[key], r.LiteralCount)
	}
	prefix, category, ok := strings.Cut(r.Source, ":")
	if !ok {
		return r.Source
	}
	name, attr, _ := strings.Cut(category, "@")
	key := "routing_category_"
	if prefix == "geoip" {
		key = "routing_geoip_"
	}
	if label := text[key+strings.ToLower(name)]; label != "" {
		if attr != "" {
			return label + " (@" + attr + ")"
		}
		return label
	}
	return category
}

// Daemon and compiler reasons are fixed English strings. Translate those
// reasons and use a fixed fallback if a snapshot carries a different value.
var routingUnavailableKeys = map[string]string{
	"not in the provider's data":                "routing_rule_not_found",
	"provider sent no geosite file":             "routing_rule_no_geosite",
	"provider sent no geoip file":               "routing_rule_no_geoip",
	"provider data not loaded":                  "routing_rule_data_missing",
	"not in the built-in country data":          "routing_rule_no_country",
	"provider rule has no usable entries":       "routing_rule_no_entries",
	"geosite file could not be downloaded":      "routing_rule_download",
	"geoip file could not be downloaded":        "routing_rule_download",
	"geosite file could not be read":            "routing_rule_unreadable",
	"geoip file could not be read":              "routing_rule_unreadable",
	"geosite data exceeds the extraction limit": "routing_rule_limit",
	"geoip data exceeds the extraction limit":   "routing_rule_limit",
	"geosite file is larger than 16 MiB":        "routing_rule_size",
	"geoip file is larger than 16 MiB":          "routing_rule_size",
}

func (r RoutingRule) reason(text map[string]string) string {
	if key := routingUnavailableKeys[r.Unavailable]; key != "" {
		return text[key]
	}
	return text["routing_rule_unavailable"]
}
