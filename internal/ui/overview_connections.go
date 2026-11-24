package ui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

const (
	connectionAvailable   = "available"
	connectionUnavailable = "unavailable"
)

type connectionGroup struct {
	Label   string
	Options []connectionOption
}

type connectionOption struct {
	Target, Label string
	Disabled      bool
}

// connectionOptions supplies both the select and the set of accepted writes.
func connectionOptions(cfg *model.Config, subs []AppliedSubscription, health map[string]ConnectionStatus, text map[string]string) []connectionGroup {
	groups := make([]connectionGroup, 0, len(cfg.Subscriptions)+1)
	for _, source := range cfg.Subscriptions {
		sub := appliedSubscriptionFor(subs, source.ID)
		group := connectionGroup{Label: sub.title(text)}
		for _, mode := range []struct{ target, key string }{
			{"auto", "overview_auto"},
			{model.SubscriptionRoundRobin, "overview_round_robin"},
			{model.SubscriptionConsistentHash, "overview_consistent_hash"},
			{model.SubscriptionStickySession, "overview_sticky_session"},
		} {
			group.Options = append(group.Options, connectionOption{Target: model.ManagedTarget(source.ID, mode.target), Label: text[mode.key]})
		}
		for _, node := range sub.Nodes {
			group.Options = append(group.Options, connectionOption{
				Target: model.ManagedTarget(source.ID, node.ID), Label: nodeLabel(node, text),
				Disabled: node.Health == connectionUnavailable,
			})
		}
		groups = append(groups, group)
	}
	if len(cfg.Connections) > 0 {
		group := connectionGroup{Label: text["overview_manual_connections"]}
		for _, conn := range cfg.Connections {
			detail := connectionProbe(health[conn.ID], text)
			if conn.Disabled {
				detail = text["overview_connection_disabled"]
			}
			group.Options = append(group.Options, connectionOption{
				Target:   conn.ID,
				Label:    strings.Join([]string{cmp.Or(conn.Name, conn.ID), connectionProtocol(conn), detail}, " · "),
				Disabled: conn.Disabled,
			})
		}
		groups = append(groups, group)
	}
	return groups
}

func selectableConnection(groups []connectionGroup, target string) bool {
	for _, group := range groups {
		for _, option := range group.Options {
			if !option.Disabled && option.Target == target {
				return true
			}
		}
	}
	return false
}

func appliedSubscriptionFor(subs []AppliedSubscription, id string) AppliedSubscription {
	for _, sub := range subs {
		if sub.ID == id {
			return sub
		}
	}
	return AppliedSubscription{ID: id}
}

func (sub AppliedSubscription) title(text map[string]string) string {
	return cmp.Or(sub.Metadata.Title, sub.ID, text["overview_subscription"])
}

func nodeLabel(node SubscriptionNode, text map[string]string) string {
	state := text["overview_not_checked"]
	switch {
	case node.Health == connectionUnavailable:
		state = text["overview_no_response"]
	case node.LatencyMS != nil:
		state = fmt.Sprintf(text["overview_latency"], *node.LatencyMS)
	case node.Health == connectionAvailable:
		state = text["overview_available"]
	}
	return cmp.Or(node.Name, node.ID) + " · " + state
}

func connectionProbe(health ConnectionStatus, text map[string]string) string {
	switch {
	case !health.Checked:
		return text["overview_not_checked"]
	case !health.Available:
		return text["overview_no_response"]
	default:
		return fmt.Sprintf(text["overview_latency"], health.LatencyMS)
	}
}

// connectionProtocol displays only the type. Link details and raw options
// stay private.
func connectionProtocol(conn model.Connection) string {
	switch conn.Type {
	case model.ConnWireGuard:
		return "WireGuard"
	case model.ConnAmneziaWG:
		return "AmneziaWG"
	case model.ConnTrustTunnel:
		return "TrustTunnel"
	case model.ConnLink:
		scheme, _, _ := strings.Cut(strings.TrimSpace(conn.Link), "://")
		switch strings.ToLower(scheme) {
		case "vless":
			return "VLESS"
		case "vmess":
			return "VMess"
		case "trojan":
			return "Trojan"
		case "ss":
			return "Shadowsocks"
		case "hysteria2", "hy2":
			return "Hysteria2"
		case "socks", "socks5":
			return "SOCKS"
		case "tuic":
			return "TUIC"
		case "anytls":
			return "AnyTLS"
		case "tt":
			return "TrustTunnel"
		}
	}
	return "sing-box"
}

type connectionSelection struct {
	Name, Detail, Reserve                 string
	Health                                string // reachability of the active path
	Expiry                                time.Time
	Class                                 stats.TargetClass
	Subscription, SubscriptionUnavailable bool
	ReserveDirect, Blocked                bool
}

func selectedConnection(cfg *model.Config, target string, subs []AppliedSubscription, health map[string]ConnectionStatus, text map[string]string) connectionSelection {
	if id, mode, managed := model.ParseManagedTarget(target); managed {
		sub := appliedSubscriptionFor(subs, id)
		selection := selectedSubscription(cfg, sub, mode, health, text)
		selection.Class = cmp.Or(health[target].Class, selection.Class)
		return selection
	}
	return selectedManualConnection(cfg, target, health, text)
}

func selectedSubscription(cfg *model.Config, sub AppliedSubscription, mode string, health map[string]ConnectionStatus, text map[string]string) connectionSelection {
	selection := connectionSelection{
		Name: sub.title(text), Expiry: setupExpiry(sub.Metadata.Usage), Subscription: true,
	}
	selection.Detail = selection.Name
	if model.IsSubscriptionBalance(mode) {
		if sub.BalanceEligible != nil {
			if *sub.BalanceEligible > 0 {
				selection.Health = connectionAvailable
				selection.Detail += " · " + fmt.Sprintf(text["overview_balancing_nodes"], *sub.BalanceEligible)
			} else {
				selection.useSubscriptionReserve(cfg, sub.ID, health, text)
			}
		}
		return selection
	}
	nodeID := mode
	if mode == "auto" {
		selection.SubscriptionUnavailable = sub.Unavailable
		if sub.Unavailable && (sub.SwitchReason == "fallback" || len(sub.Nodes) == 0) {
			selection.useSubscriptionReserve(cfg, sub.ID, health, text)
			return selection
		}
		nodeID = sub.ActiveNode
	}
	if i := slices.IndexFunc(sub.Nodes, func(node SubscriptionNode) bool { return node.ID == nodeID }); i >= 0 {
		node := sub.Nodes[i]
		selection.Detail += " · " + nodeLabel(node, text)
		selection.Health = node.Health
	} else if mode != "auto" {
		selection.useSubscriptionReserve(cfg, sub.ID, health, text)
	}
	return selection
}

func selectedManualConnection(cfg *model.Config, target string, health map[string]ConnectionStatus, text map[string]string) connectionSelection {
	active := cmp.Or(health[target].Active, target)
	selection := connectionSelection{Class: connectionClass(target, health)}
	if active == model.TargetBlock {
		selection.Blocked = true
		return selection
	}
	probe := health[active]
	if probe.Checked {
		selection.Health = connectionUnavailable
		if probe.Available {
			selection.Health = connectionAvailable
		}
	}
	switch selection.Class {
	case stats.TargetDirect:
		selection.Detail = text["overview_direct"]
		if active != target {
			selection.Reserve = selection.Detail
		}
		return selection
	case stats.TargetMixed:
		selection.Name = cmp.Or(connectionName(cfg, target), target)
		return selection
	}
	for _, conn := range cfg.Connections {
		if conn.ID != active || conn.Disabled {
			continue
		}
		selection.Detail = cmp.Or(conn.Name, conn.ID) + " · " + connectionProbe(probe, text)
		return selection
	}
	selection.Blocked = true
	return selection
}

func (s *connectionSelection) useSubscriptionReserve(cfg *model.Config, id string, health map[string]ConnectionStatus, text map[string]string) {
	s.SubscriptionUnavailable = true
	for _, source := range cfg.Subscriptions {
		if source.ID != id {
			continue
		}
		// A configured reserve can itself use a failover chain. Read the
		// probe of the selected member, as for an ordinary manual target.
		reserve := selectedManualConnection(cfg, source.Fallback, health, text)
		s.Class = reserve.Class
		if reserve.Blocked {
			return
		}
		s.Health = reserve.Health
		s.ReserveDirect = reserve.Class == stats.TargetDirect || health[source.Fallback].Active == model.TargetDirect
		if s.ReserveDirect {
			s.Reserve = text["overview_direct"]
		} else {
			s.Reserve = connectionName(cfg, source.Fallback)
		}
		return
	}
}

func connectionName(cfg *model.Config, target string) string {
	for _, conn := range cfg.Connections {
		if conn.ID == target {
			return cmp.Or(conn.Name, conn.ID)
		}
	}
	return ""
}

func connectionClass(target string, health map[string]ConnectionStatus) stats.TargetClass {
	if target == model.TargetDirect {
		return stats.TargetDirect
	}
	return health[target].Class
}
