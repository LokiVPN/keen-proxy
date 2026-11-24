package ui

import (
	"cmp"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

type connectionsPage struct {
	Revision      string
	Draft         bool
	Subscriptions []connectionSubscriptionView
	Rows          []manualConnectionView
	Reserve       []connectionOption
}

type connectionSubscriptionView struct {
	Fallback   string
	AllowUnset bool
	Nodes      subscriptionNodesView
}

type subscriptionNodesView struct {
	ID, Title, Summary    string
	Status                overviewChip
	ViewOnly, CheckingAll bool
	Rows                  []connectionNodeView
	Text                  map[string]string
}

type connectionNodeView struct {
	ID, Name, Probe string
	Status          overviewChip
	Checking        bool
}

type manualConnectionView struct {
	ID, Name, URL, Type, Reserve string
	Probe                        string
	Failed, Disabled, Enabled    bool
}

func connectionsView(cfg, draft *model.Config, subs []AppliedSubscription, health map[string]ConnectionStatus, viewOnly bool, text map[string]string) *connectionsPage {
	settings := cmp.Or(draft, cfg)
	view := &connectionsPage{Revision: Revision(cfg), Draft: draft != nil}
	now := time.Now()
	for i, source := range cfg.Subscriptions {
		nodes := connectionNodes(appliedSubscriptionFor(subs, source.ID), viewOnly, now, text)
		view.Subscriptions = append(view.Subscriptions, connectionSubscriptionView{
			Fallback: settings.Subscriptions[i].Fallback, AllowUnset: source.Fallback == "", Nodes: nodes,
		})
	}
	if len(settings.Subscriptions) > 0 {
		view.Reserve = connectionReserveOptions(cfg, text)
	}
	for i, conn := range cfg.Connections {
		probe := health[conn.ID]
		row := manualConnectionView{
			ID: conn.ID, Name: cmp.Or(conn.Name, conn.ID), URL: "/connections/" + url.PathEscape(conn.ID),
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
	targets := cfg.SubscriptionFallbackTargets()
	options := make([]connectionOption, 0, len(targets))
	for _, target := range targets {
		options = append(options, connectionOption{Target: target, Label: labels[target]})
	}
	return options
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

func connectionNodes(sub AppliedSubscription, viewOnly bool, now time.Time, text map[string]string) subscriptionNodesView {
	view := subscriptionNodesView{
		ID: sub.ID, Title: fmt.Sprintf(text["connections_subscription"], sub.title(text)),
		Status: connectionSubscriptionStatus(sub, now, text), CheckingAll: sub.CheckingAll,
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
	row := connectionNodeView{ID: node.ID, Name: cmp.Or(node.Name, node.ID), Checking: node.Checking}
	switch {
	case node.Checking:
		row.Probe = text["connections_checking"]
	case node.Health == connectionUnavailable:
		row.Probe = text["overview_no_response"]
	case node.LatencyMS != nil:
		row.Probe = fmt.Sprintf(text["overview_latency"], *node.LatencyMS)
	case node.Health == connectionAvailable:
		row.Probe = text["overview_available"]
	default:
		row.Probe = text["overview_not_checked"]
	}
	if node.Health == connectionUnavailable {
		row.Status = overviewChip{text["connections_node_unavailable"], "warn"}
	} else if node.ID == active {
		row.Status = overviewChip{text["connections_active_node"], "ok"}
	}
	return row
}
