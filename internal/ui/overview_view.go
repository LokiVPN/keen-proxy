package ui

import (
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const expiryWarning = 7 * 24 * time.Hour

type overviewPage struct {
	Rev                          string
	Paused, CanSelect            bool
	Status                       overviewChip
	StatusDetail                 string
	Subscriptions                []overviewSubscription
	Main, MissingTarget, Current string
	Choices                      []connectionGroup
	Routing, RoutingDetail       string
	Devices, NewDevices          string
}

type overviewChip struct{ Label, Class string }

type overviewSubscription struct {
	ID, Title, Expiry, Notice, AccountURL string
	ReplaceURL                            string
	Status                                overviewChip
	ExpiryReminder                        string
	DuplicateTitle, ShowRefreshFailure    bool
	Traffic                               string
	Used, Total                           int64
	LastUpdated, NextUpdate               string
}

type trafficView struct {
	Incoming, Outgoing string
	Chart              template.HTML
}

func (p pages) renderOverview(w http.ResponseWriter, r *http.Request, code int, cfg *model.Config, messageKey string) {
	if cfg == nil {
		if code == http.StatusOK {
			code, messageKey = http.StatusServiceUnavailable, "setup_unavailable"
		}
		p.renderPage(w, r, code, "KeenProxy", messageKey)
		return
	}
	data := p.opts.pageData(r)
	data.Title, data.ActiveTab, data.SignedIn = "KeenProxy", "/", true
	data.ViewOnly = p.role(r) == RoleView
	data.Flash, data.Message = takeFlash(w, r, data.Text), data.Text[messageKey]
	status, subscriptions := p.deps.OverviewStatus(), p.deps.Subscriptions()
	series := p.deps.TrafficSeries()
	now := time.Now()
	data.Overview = makeOverview(cfg, status, subscriptions, now, data.Lang)
	data.Traffic = overviewTraffic(series, now, data.Lang)
	render(w, r, code, "overview", data)
}

func makeOverview(cfg *model.Config, status OverviewStatus, subs []AppliedSubscription, now time.Time, lang string) *overviewPage {
	text := translations[lang]
	titles := subscriptionTitlesFor(cfg, subs)
	page := &overviewPage{
		Rev: Revision(cfg), Paused: cfg.Paused, Choices: connectionOptions(cfg, subs, status.Connections, text),
	}
	network := cfg.HomeNetwork()
	if network != nil {
		page.Main = network.Target
		for _, group := range page.Choices {
			page.CanSelect = page.CanSelect || slices.ContainsFunc(group.Options, func(option connectionOption) bool { return !option.Disabled })
		}
	}
	mainSource, _, _ := model.ParseManagedTarget(page.Main)
	for _, source := range cfg.Subscriptions {
		view := subscriptionView(appliedSubscriptionFor(subs, source.ID), titles, now, lang)
		if source.ID == mainSource {
			page.Subscriptions = slices.Insert(page.Subscriptions, 0, view)
		} else {
			page.Subscriptions = append(page.Subscriptions, view)
		}
	}
	page.setMissingTarget(text)
	page.Devices = text["overview_no_devices"]
	if status.Devices > 0 {
		page.Devices = fmt.Sprintf(text["overview_device_count"], status.ManagedDevices, status.Devices)
	}
	target, activeHome, mixedHome := overviewHomePath(network, status.HomeTargets)
	selection := selectedConnection(cfg, target, subs, titles, status.Connections, text)
	if network != nil {
		page.NewDevices = text["overview_new_devices_policy"]
		if network.Mode == model.ModeOff || (network.Mode == model.ModeFull && selection.Class == stats.TargetDirect) {
			page.NewDevices = text["overview_new_devices_direct"]
		}
		current := selection.Detail
		switch {
		case selection.Reserve != "":
			current = selection.withSubscription(selection.Reserve)
		case selection.Class == stats.TargetMixed:
			current = selection.Name
		}
		if status.Ready && !cfg.Paused && activeHome && !mixedHome && !selection.Blocked && current != "" {
			page.Current = fmt.Sprintf(text["overview_current_connection"], current)
		}
	}
	page.Status, page.StatusDetail = overviewStatus(cfg.Paused, status, network, target, activeHome, mixedHome, selection, now, text)
	main := selection
	if target != page.Main {
		main = selectedConnection(cfg, page.Main, subs, titles, status.Connections, text)
	}
	page.Routing, page.RoutingDetail = routingSummary(cfg, network, main, status, subs, titles, text)
	return page
}

func (p *overviewPage) setMissingTarget(text map[string]string) {
	for _, group := range p.Choices {
		if slices.ContainsFunc(group.Options, func(option connectionOption) bool { return option.Target == p.Main }) {
			return
		}
	}
	switch p.Main {
	case "":
		p.MissingTarget = text["overview_choose_connection"]
	case model.TargetDirect:
		p.MissingTarget = text["overview_direct"]
	default:
		p.MissingTarget = text["overview_missing_connection"]
	}
}

func overviewHomePath(network *model.Network, targets []string) (target string, active, mixed bool) {
	if network == nil {
		return "", false, false
	}
	if network.Mode == model.ModeOff {
		if len(targets) == 1 {
			return targets[0], true, false
		}
		return network.Target, len(targets) > 0, len(targets) > 1
	}
	return network.Target, true, len(targets) > 1 || len(targets) == 1 && targets[0] != network.Target
}

func overviewStatus(paused bool, status OverviewStatus, network *model.Network, target string, activeHome, mixedHome bool, selection connectionSelection, now time.Time, text map[string]string) (overviewChip, string) {
	outage := overviewChip{text["overview_no_connection"], "warn"}
	detail := selection.Detail
	if selection.Class == stats.TargetMixed {
		detail = fmt.Sprintf(text["overview_follow_connection"], selection.Name)
	}
	if mixedHome {
		detail = text["overview_device_routing_hint"]
	}
	if status.Devices > 0 {
		detail = fmt.Sprintf(text["overview_device_count"], status.ManagedDevices, status.Devices) + " · " + detail
	}
	// The first matching status wins. For an active Home target, reachability
	// follows the selected path before subscription state or static route class.
	switch {
	case paused:
		return overviewChip{text["overview_disabled"], ""}, text["overview_paused_hint"]
	case !status.Ready:
		return outage, text["overview_engine_down"]
	case network == nil:
		return outage, text["overview_no_home"]
	case !activeHome:
		return overviewChip{text["overview_home_off"], ""}, text["overview_home_off_hint"]
	case mixedHome:
		return overviewChip{text["overview_device_routing"], ""}, detail
	case target == "":
		return outage, text["overview_choose_connection"]
	case selection.Health == connectionUnavailable:
		if selection.Reserve != "" {
			return outage, selection.withSubscription(text["overview_reserve_down"])
		}
		if selection.Subscription {
			return outage, selection.withSubscription(text["overview_subscription_down"])
		}
		return outage, text["overview_connection_down"]
	case selection.SubscriptionUnavailable && !selection.Blocked && selection.Reserve != "":
		if selection.ReserveDirect {
			return overviewChip{text["overview_direct"], ""}, selection.withSubscription(text["overview_direct_reserve"])
		}
		return overviewChip{text["overview_reserve_connection"], ""}, selection.withSubscription(fmt.Sprintf(text["overview_using_reserve"], selection.Reserve))
	case selection.SubscriptionUnavailable || (selection.Subscription && selection.Blocked):
		return outage, selection.withSubscription(text["overview_subscription_down"])
	case selection.Blocked:
		return outage, text["overview_connection_down"]
	case selection.Class == stats.TargetDirect:
		detail := text["overview_direct_hint"]
		if selection.Reserve != "" {
			detail = selection.withSubscription(text["overview_direct_reserve"])
		}
		return overviewChip{text["overview_direct"], ""}, detail
	case expired(selection.Expiry, now):
		return overviewChip{text["overview_subscription_expired"], "warn"}, detail
	case expiring(selection.Expiry, now):
		return overviewChip{text["overview_subscription_expiring"], "caut"}, detail
	case selection.Class == stats.TargetMixed:
		return overviewChip{text["overview_connection_routing"], ""}, detail
	case selection.Class == stats.TargetVPN && selection.Health == connectionAvailable:
		return overviewChip{text["overview_working"], "ok"}, detail
	default:
		return overviewChip{text["overview_checking"], ""}, detail
	}
}

func expired(expiry, now time.Time) bool { return !expiry.IsZero() && !expiry.After(now) }

func expiring(expiry, now time.Time) bool {
	return expiry.After(now) && !expiry.After(now.Add(expiryWarning))
}

func subscriptionView(sub AppliedSubscription, titles subscriptionTitles, now time.Time, lang string) overviewSubscription {
	text := translations[lang]
	metadata := sub.Metadata
	view := overviewSubscription{
		ID: sub.ID, Title: titles.title(sub.ID, text), DuplicateTitle: titles.duplicate(sub.ID, text),
		Notice: metadata.Announce, AccountURL: metadata.ProfileURL,
		ReplaceURL: subscriptionPath(sub.ID) + "/replace", Traffic: setupTraffic(metadata.Usage, lang),
	}
	expiry := setupExpiry(metadata.Usage)
	failed := sub.State != "" && sub.State != "pending" && sub.State != subscription.StateReady
	view.ShowRefreshFailure = failed
	if !expiry.IsZero() {
		view.Expiry = fmt.Sprintf(text["overview_until"], setupDate(expiry, text))
	}
	switch {
	case expired(expiry, now):
		view.Status = overviewChip{text["setup_expired"], "warn"}
		view.Expiry = setupDate(expiry, text)
		view.ExpiryReminder = text["overview_renew_expired"]
	case expiring(expiry, now):
		view.Status = overviewChip{text["overview_expiring"], "caut"}
		view.Expiry = setupRemaining(expiry, now, lang)
		view.ExpiryReminder = fmt.Sprintf(text["overview_renew_before"], setupDate(expiry, text))
	case sub.State == subscription.StateHWIDLimit:
		view.Status = overviewChip{text["setup_limit"], "warn"}
	case failed:
		view.Status = overviewChip{text["overview_last_update_failed"], "warn"}
		view.ShowRefreshFailure = false
	case len(sub.Nodes) > 0:
		view.Status = overviewChip{text["setup_active"], "ok"}
	default:
		view.Status = overviewChip{text["overview_subscription_pending"], ""}
	}
	if usage := metadata.Usage; usage != nil && usage.Total > 0 {
		view.Total = usage.Total
		uploaded := min(max(0, usage.Upload), view.Total)
		view.Used = uploaded + min(max(0, usage.Download), view.Total-uploaded)
	}
	if !sub.LastSuccess.IsZero() {
		view.LastUpdated = fmt.Sprintf(text["overview_last_update"], overviewTimestamp(sub.LastSuccess, text))
	}
	if sub.Refreshing {
		view.NextUpdate = text["overview_refreshing"]
	} else if !sub.NextRefresh.IsZero() {
		view.NextUpdate = fmt.Sprintf(text["overview_next_update"], overviewTimestamp(sub.NextRefresh, text))
	}
	return view
}

func overviewTimestamp(at time.Time, text map[string]string) string {
	at = at.Local()
	return fmt.Sprintf(text["overview_date_time"], setupDate(at, text), at.Format("15:04"))
}

func routingSummary(cfg *model.Config, network *model.Network, main connectionSelection, status OverviewStatus, subs []AppliedSubscription, titles subscriptionTitles, text map[string]string) (string, string) {
	if network == nil {
		return text["overview_no_home"], ""
	}
	rules := cfg.ActiveProviderRules()
	mode := text["overview_route_own"]
	remaining := routingRemainingChoice(network)
	var details []string
	switch {
	case network.Mode == model.ModeOff:
		mode = text["overview_home_off"]
		if len(status.HomeTargets) > 0 {
			mode = text["overview_existing_device_policy"]
		}
	case network.Mode == model.ModeSplit && rules != nil && remaining != "":
		mode = fmt.Sprintf(text["overview_route_provider"], titles.label(rules.Source, text))
		profileDirect := status.RulesSource == rules.Source && status.RulesHasProfile && !status.RulesGlobalProxy
		details = append(details, providerRemainingDetail(remaining, main, profileDirect, text))
	case network.Mode == model.ModeFull || (network.Default != "" && network.Default != model.TargetDirect && network.Default != model.DefaultProfile):
		selection := main
		if network.Mode != model.ModeFull && network.Default != network.Target {
			selection = selectedConnection(cfg, network.Default, subs, titles, status.Connections, text)
		}
		mode = text["overview_route_custom"]
		switch selection.Class {
		case stats.TargetMixed:
			mode = fmt.Sprintf(text["overview_follow_connection"], selection.Name)
		case stats.TargetVPN:
			mode = text["overview_route_all"]
		case stats.TargetDirect:
			if network.Mode == model.ModeFull {
				mode = text["overview_direct"]
			}
		}
	case network.Default == model.DefaultProfile:
		mode = text["overview_route_profile"]
	case rules != nil:
		mode = text["overview_route_custom"]
	}
	if rules != nil && status.RulesSource == rules.Source {
		switch status.RulesState {
		case "ready", "partial":
			details = append(details, fmt.Sprintf(text["overview_rule_count"], status.RulesActive, status.RulesTotal))
		case "pending":
			details = append(details, text["setup_rules_pending"])
		case "withheld":
			details = append(details, text["setup_rules_withheld"])
		case "failed":
			details = append(details, text["overview_rules_failed"])
		}
	}
	count := 0
	for _, group := range cfg.Groups {
		if group.Name == "own-vpn" || group.Name == "own-direct" {
			count += len(group.Entries)
		}
	}
	details = append(details, fmt.Sprintf(text["overview_own_count"], count))
	return mode, strings.Join(details, " · ")
}

// providerRemainingDetail describes the applied split default, following the
// main connection when the profile calls for it or no profile applies.
func providerRemainingDetail(choice string, main connectionSelection, profileDirect bool, text map[string]string) string {
	key := "routing_rest_main"
	switch {
	case choice == model.TargetDirect, choice == model.DefaultProfile && profileDirect,
		main.ReserveDirect, main.Class == stats.TargetDirect:
		key = "routing_rest_direct"
	case main.Class == stats.TargetVPN:
		key = "routing_rest_vpn"
	case main.Class == stats.TargetBlock:
		key = "routing_rest_blocked"
	}
	return fmt.Sprintf(text["overview_route_remaining"], text[key])
}

func overviewTraffic(series []stats.Point, now time.Time, lang string) trafficView {
	return trafficChart(series, now, lang, "overview_chart_label")
}

func trafficChart(series []stats.Point, now time.Time, lang, labelKey string) trafficView {
	text := translations[lang]
	traffic := trafficView{Chart: Chart(series, now, lang, text[labelKey])}
	for i := len(series) - 1; i >= 0; i-- {
		point := series[i]
		if point.T < now.Add(-chartWindow).UnixMilli() {
			break
		}
		if point.T <= now.UnixMilli() {
			traffic.Incoming = fmt.Sprintf(text["overview_incoming"], trafficRate(point.Down, lang))
			traffic.Outgoing = fmt.Sprintf(text["overview_outgoing"], trafficRate(point.Up, lang))
			break
		}
	}
	return traffic
}

func trafficRate(rate float64, lang string) string {
	return formatTrafficNumber(validTrafficRate(rate)/1e6, 1, lang)
}
