package ui

import (
	"cmp"
	"fmt"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

type connectionsPage struct {
	Revision      string
	AddPath       string
	Draft         bool
	Subscriptions []connectionSubscriptionView
	Rows          []manualConnectionView
	Reserve       []connectionOption
	References    []connectionReference
}

type connectionSubscriptionView struct {
	Fallback   string
	AllowUnset bool
	Path       string
	Nodes      subscriptionNodesView
}

type subscriptionNodesView struct {
	ID, Title, Summary    string
	RulesNotice           string
	Status                overviewChip
	DuplicateTitle        bool
	ViewOnly, CheckingAll bool
	Rows                  []connectionNodeView
	Text                  map[string]string
}

type connectionNodeView struct {
	ID, Name, Probe string
	Checking        bool
	Current         bool
	Unavailable     bool
}

type manualConnectionView struct {
	SwitchField, Name, URL, Type, Reserve string
	Probe                                 string
	Failed, Disabled, Enabled             bool
}

func connectionsView(cfg, draft *model.Config, subs []AppliedSubscription, health map[string]ConnectionStatus, viewOnly bool, text map[string]string) *connectionsPage {
	settings := cmp.Or(draft, cfg)
	view := &connectionsPage{Revision: Revision(cfg), AddPath: subscriptionNewPath}
	now := time.Now()
	titles := subscriptionTitlesFor(cfg, subs)
	for i, source := range cfg.Subscriptions {
		nodes := connectionNodes(appliedSubscriptionFor(subs, source.ID), titles, viewOnly, now, text)
		fallback := settings.Subscriptions[i].Fallback
		view.Draft = view.Draft || fallback != source.Fallback
		view.Subscriptions = append(view.Subscriptions, connectionSubscriptionView{
			Fallback: connectionIDSegment(fallback), AllowUnset: source.Fallback == "",
			Path: subscriptionPath(source.ID), Nodes: nodes,
		})
	}
	if len(settings.Subscriptions) > 0 {
		view.Reserve = connectionReserveOptions(cfg, text)
	}
	for i, conn := range cfg.Connections {
		probe := health[conn.ID]
		view.Draft = view.Draft || settings.Connections[i].Disabled != conn.Disabled
		row := manualConnectionView{
			SwitchField: connectionEnabledField(conn.ID), Name: cmp.Or(conn.Name, conn.ID), URL: connectionDetailPath(conn.ID),
			Type: connectionProtocol(conn), Reserve: connectionReserveChain(cfg, conn.ID, text),
			Probe: connectionProbe(probe, text), Failed: probe.Checked && !probe.Available,
			Disabled: conn.Disabled, Enabled: !settings.Connections[i].Disabled,
		}
		if conn.Disabled {
			row.Probe = text["overview_connection_disabled"]
			row.Failed = false
		}
		view.Rows = append(view.Rows, row)
	}
	return view
}

// connectionReserveOptions labels the model's choices, including disabled
// manual connections whose own reserves still apply.
func connectionReserveOptions(cfg *model.Config, text map[string]string) []connectionOption {
	labels := manualReserveLabels(cfg, text)
	targets := cfg.SubscriptionFallbackTargets()
	options := make([]connectionOption, 0, len(targets))
	for _, target := range targets {
		options = append(options, connectionOption{Target: connectionIDSegment(target), Label: labels[target]})
	}
	return options
}

func manualReserveLabels(cfg *model.Config, text map[string]string) map[string]string {
	labels := make(map[string]string, len(cfg.Connections)+2)
	for _, conn := range cfg.Connections {
		label := cmp.Or(conn.Name, conn.ID) + " · " + connectionProtocol(conn)
		if conn.Disabled {
			label += " · " + text["overview_connection_disabled"]
		}
		labels[conn.ID] = label
	}
	labels[model.TargetDirect] = text["connections_reserve_direct"]
	labels[model.TargetBlock] = text["connections_reserve_block"]
	return labels
}

func connectionReserveChain(cfg *model.Config, id string, text map[string]string) string {
	var names []string
	for _, target := range cfg.Chain(id)[1:] {
		name := cmp.Or(connectionName(cfg, target), target)
		if target == model.TargetDirect {
			name = text["connections_direct"]
		}
		names = append(names, name)
	}
	return strings.Join(names, " → ")
}

func connectionNodes(sub AppliedSubscription, titles subscriptionTitles, viewOnly bool, now time.Time, text map[string]string) subscriptionNodesView {
	view := subscriptionNodesView{
		ID: sub.ID, Title: titles.title(sub.ID, text), DuplicateTitle: titles.duplicate(sub.ID, text),
		RulesNotice: providerRulesNotice(sub.RulesState, text),
		Status:      connectionSubscriptionStatus(sub, now, text), CheckingAll: sub.CheckingAll,
		ViewOnly: viewOnly, Text: text,
	}
	var summary []string
	if !sub.LastSuccess.IsZero() {
		summary = append(summary, fmt.Sprintf(text["connections_updated"], overviewTimestamp(sub.LastSuccess, text)))
	}
	summary = append(summary, fmt.Sprintf(text["connections_node_count"], len(sub.Nodes)))
	if sub.Skipped > 0 {
		summary = append(summary, fmt.Sprintf(text["connections_skipped"], sub.Skipped))
	}
	view.Summary = strings.Join(summary, " · ")
	for _, node := range sub.Nodes {
		view.Rows = append(view.Rows, connectionNode(node, sub.ActiveNode, text))
	}
	return view
}

func connectionSubscriptionStatus(sub AppliedSubscription, now time.Time, text map[string]string) overviewChip {
	switch {
	case expired(setupExpiry(sub.Metadata.Usage), now):
		return overviewChip{text["setup_expired"], "warn"}
	case sub.State == subscription.StateHWIDLimit:
		return overviewChip{text["setup_limit"], "warn"}
	case sub.State == "", sub.State == "pending":
		return overviewChip{text["overview_subscription_pending"], ""}
	case sub.State != subscription.StateReady:
		return overviewChip{text["overview_last_update_failed"], "warn"}
	default:
		return overviewChip{text["connections_ready"], "ok"}
	}
}

func connectionNode(node SubscriptionNode, active string, text map[string]string) connectionNodeView {
	row := connectionNodeView{
		ID: node.ID, Name: cmp.Or(node.Name, node.ID), Checking: node.Checking,
		Current: active != "" && node.ID == active, Unavailable: node.Health == connectionUnavailable,
	}
	switch {
	case node.Checking:
		row.Probe = text["connections_checking"]
	case row.Unavailable:
		row.Probe = text["overview_no_response"]
	case node.LatencyMS != nil:
		row.Probe = fmt.Sprintf(text["overview_latency"], *node.LatencyMS)
	case node.Health == connectionAvailable:
		row.Probe = text["overview_available"]
	default:
		row.Probe = text["overview_not_checked"]
	}
	return row
}
