package ui

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

type routingPage struct {
	Revision, Mode                   string
	Unavailable, CustomMode          string
	CanProvider, CanAll, OtherGroups bool
	VPN, Direct                      *routingList
	ProviderMode, ProviderHeading    string
	RuleState, SubscriptionUpdated   string
	Unmatched                        string
	RuleGroups                       []routingRuleGroup
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
	page := routingPage{Revision: Revision(cfg), VPN: &routingList{}, Direct: &routingList{}}
	network := homeNetwork(cfg)
	if network == nil {
		page.Unavailable = text["overview_no_home"]
		return &page
	}
	if network.Mode == model.ModeFull {
		page.Unavailable = text["routing_full_policy"]
		return &page
	}
	settings := cfg.ActiveProviderRules()
	page.Mode = routingMode(network, settings)
	if page.Mode == "" {
		page.CustomMode = text["routing_custom_mode"]
	}
	source := routingRulesSource(cfg, network)
	page.CanAll = routingHasMain(network)
	page.CanProvider = page.CanAll && source != ""
	page.ProviderMode, page.ProviderHeading = text["routing_mode_provider"], text["routing_provider_rules"]
	if source != "" {
		sub := appliedSubscriptionFor(p.deps.Subscriptions(), source)
		if name := sub.Metadata.Title; name != "" {
			page.ProviderMode = fmt.Sprintf(text["routing_mode_named_provider"], name)
			page.ProviderHeading = fmt.Sprintf(text["routing_named_provider_rules"], name)
		}
		if !sub.LastSuccess.IsZero() {
			page.SubscriptionUpdated = fmt.Sprintf(text["routing_subscription_updated"], overviewTimestamp(sub.LastSuccess, text))
		}
	}
	// The first reserved group of each name is the same group the form edits.
	var hasVPN, hasDirect bool
	for _, group := range cfg.Groups {
		switch {
		case group.Name == ownVPNGroup && !hasVPN:
			page.VPN.Value, hasVPN = strings.Join(group.Entries, "\n"), true
		case group.Name == ownDirectGroup && !hasDirect:
			page.Direct.Value, hasDirect = strings.Join(group.Entries, "\n"), true
		default:
			page.OtherGroups = true
		}
	}
	if draft != nil {
		page.Mode = draft.Mode
		if draft.VPN != nil {
			page.VPN = draft.VPN
		}
		if draft.Direct != nil {
			page.Direct = draft.Direct
		}
	}
	page.setRules(p.routingRules(cfg), settings, draft, text)
	return &page
}

// routingMode recognizes the defaults written by this page. A custom
// configuration is left unselected until an administrator chooses a mode.
func routingMode(network *model.Network, settings *model.ProviderRulesSettings) string {
	switch {
	case settings != nil && network.Default == model.DefaultProfile && routingHasMain(network):
		return routingProvider
	case settings != nil:
		return ""
	case network.Default == "" || network.Default == model.TargetDirect:
		return routingOwn
	case network.Default == network.Target && routingHasMain(network):
		return routingAll
	}
	return ""
}

func (p pages) routingRules(cfg *model.Config) RoutingRules {
	settings := cfg.ActiveProviderRules()
	if settings == nil {
		return RoutingRules{State: "off"}
	}
	rules := p.deps.ProviderRules()
	if rules.Source != settings.Source {
		return RoutingRules{State: "pending"}
	}
	return rules
}

func (p *routingPage) setRules(rules RoutingRules, settings *model.ProviderRulesSettings, draft *routingDraft, text map[string]string) {
	switch rules.State {
	case "off":
		p.RuleState = text["routing_rules_on_save"]
	case "pending":
		p.RuleState = text["setup_rules_pending"]
	case "withheld":
		p.RuleState = text["setup_rules_withheld"]
	case "failed":
		p.RuleState = text["overview_rules_failed"]
	}
	if rules.HasProfile {
		p.Unmatched = text["routing_rest_direct"]
		if rules.GlobalProxy {
			p.Unmatched = text["routing_rest_vpn"]
		}
	}
	var disabled []string
	if settings != nil {
		disabled = settings.Disabled
	}
	for _, action := range []string{"proxy", "direct", "block"} {
		group := routingRuleGroup{Label: text["routing_action_"+action]}
		for _, rule := range rules.Rules {
			if rule.Action != action || rule.private() {
				continue
			}
			row := routingRuleRow{Key: rule.Key, Label: rule.label(text), Checked: !slices.Contains(disabled, rule.Key)}
			if rule.Unavailable != "" {
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

func (r RoutingRule) switchable() bool {
	return r.Key != "" && r.Unavailable == "" && !r.private() && (r.Action == "proxy" || r.Action == "direct" || r.Action == "block")
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
