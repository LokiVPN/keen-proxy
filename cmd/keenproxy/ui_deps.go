package main

import (
	"context"
	"net/http"
	"net/netip"
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/api"
	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

type managementDaemon interface {
	api.Daemon
	PreviewSubscriptionDetails(context.Context, subscription.Source) daemon.SubscriptionPreviewDetails
	ApplyIfCurrent(context.Context, *model.Config, string) error
	ApplySubscriptionPreview(context.Context, *model.Config, string, subscription.PreviewRef) error
	RoutingStatus() daemon.RoutingStatus
	ProviderRules() (compile.ProviderRules, *model.ProviderRulesSettings, daemon.ProviderRulesState)
	Subscriptions() []daemon.SubscriptionStatus
	TrafficSeries() []stats.Point
	RefreshSubscriptionIfCurrent(id, revision string) error
	CheckSubscriptionIfCurrent(source, node, revision string) error
}

// uiDeps gives pages display snapshots and revision-checked management operations.
type uiDeps struct {
	daemon managementDaemon
}

func (d uiDeps) Config() *model.Config {
	return d.daemon.Config()
}

func (d uiDeps) PreviewSubscription(ctx context.Context, source subscription.Source) ui.SetupPreview {
	details := d.daemon.PreviewSubscriptionDetails(ctx, source)
	status := details.Status
	result := ui.SetupPreview{
		State: status.State, Metadata: status.Metadata, NodeCount: len(status.Nodes),
		Routing: details.Routing, RulesState: string(status.RulesState), PreviewID: details.PreviewID,
	}
	const maxNames = 6
	for _, node := range status.Nodes[:min(len(status.Nodes), maxNames)] {
		result.NodeNames = append(result.NodeNames, node.Name)
	}
	return result
}

func (uiDeps) LANPrefix(iface string) (netip.Prefix, error) {
	return lanPrefix(iface, lanPrefixes)
}

func (d uiDeps) Apply(ctx context.Context, cfg *model.Config, revision string) error {
	ctx = daemon.WithActor(ctx, daemon.Actor{Who: "user"})
	return d.daemon.ApplyIfCurrent(ctx, cfg, revision)
}

func (uiDeps) ValidateConnection(ctx context.Context, cfg *model.Config, id string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	// Compile a replacement even when its saved switch is off. Apply receives
	// the original switch state and all existing references.
	validation := *cfg
	validation.Connections = slices.Clone(cfg.Connections)
	for i := range validation.Connections {
		if validation.Connections[i].ID == id {
			validation.Connections[i].Disabled = false
			break
		}
	}
	return api.ValidateEngineProfiles(ctx, &validation)
}

func (d uiDeps) ApplySubscriptionPreview(ctx context.Context, cfg *model.Config, revision string, checked subscription.PreviewRef) error {
	ctx = daemon.WithActor(ctx, daemon.Actor{Who: "user"})
	return d.daemon.ApplySubscriptionPreview(ctx, cfg, revision, checked)
}

func (d uiDeps) OverviewStatus() ui.OverviewStatus {
	routing := d.daemon.RoutingStatus()
	status := ui.OverviewStatus{
		Ready: routing.Ready, Devices: routing.Devices, ManagedDevices: routing.ManagedDevices,
		Connections: make(map[string]ui.ConnectionStatus, len(routing.Health)),
	}
	for id, health := range routing.Health {
		status.Connections[id] = ui.ConnectionStatus{
			Checked: !health.Checked.IsZero(), Available: health.OK, LatencyMS: health.Latency,
		}
	}
	for id, failover := range routing.Failover {
		connection := status.Connections[id]
		connection.Active = failover.Active
		connection.ActiveClass = routing.ActiveTargetClasses[id]
		status.Connections[id] = connection
	}
	for id, class := range routing.TargetClasses {
		connection := status.Connections[id]
		connection.Class = class
		status.Connections[id] = connection
	}
	rules, settings, state := d.daemon.ProviderRules()
	status.RulesState = string(state)
	if settings != nil && (state == daemon.ProviderRulesReady || state == daemon.ProviderRulesPartial) {
		status.RulesTotal = len(rules.Rules)
		disabled := settings.DisabledRuleKeys()
		for _, rule := range rules.Rules {
			if rule.Unavailable == "" && !disabled[rule.Key] {
				status.RulesActive++
			}
		}
	}
	return status
}

func (d uiDeps) Devices() []ui.DiscoveredDevice {
	observed := d.daemon.Devices()
	list := make([]ui.DiscoveredDevice, 0, len(observed))
	for _, dev := range observed {
		list = append(list, ui.DiscoveredDevice{MAC: dev.MAC, IP: dev.IP, Name: dev.Hostname})
	}
	return list
}

func (d uiDeps) ProviderRules() ui.RoutingRules {
	rules, settings, state := d.daemon.ProviderRules()
	view := ui.RoutingRules{
		State: string(state), HasProfile: rules.RouteOrder != "", GlobalProxy: rules.GlobalProxy,
	}
	if settings == nil {
		return view
	}
	view.Source = settings.Source
	view.Rules = make([]ui.RoutingRule, 0, len(rules.Rules))
	for _, rule := range rules.Rules {
		item := ui.RoutingRule{Key: rule.Key, Action: rule.Action, Kind: rule.Kind, Source: rule.Source, Unavailable: rule.Unavailable}
		if rule.Source == "literals" {
			item.LiteralCount = len(rule.Suffix) + len(rule.Full) + len(rule.Keyword) + len(rule.Regex) + len(rule.CIDR)
		}
		view.Rules = append(view.Rules, item)
	}
	return view
}

func (d uiDeps) Subscriptions() []ui.AppliedSubscription {
	sources := d.daemon.Subscriptions()
	list := make([]ui.AppliedSubscription, 0, len(sources))
	for _, status := range sources {
		view := ui.AppliedSubscription{
			ID: status.ID, State: status.State, Metadata: status.Metadata, ActiveNode: status.ActiveNode,
			Unavailable: status.Unavailable, SwitchReason: status.SwitchReason,
			RulesState: string(status.RulesState), RulesWithheld: status.RulesWithheld,
			BalanceEligible: status.BalanceEligible, Refreshing: status.Refreshing,
			Skipped: status.Skipped, CheckingAll: status.CheckProgress != nil,
			Nodes: make([]ui.SubscriptionNode, 0, len(status.Nodes)),
		}
		if status.LastSuccess != nil {
			view.LastSuccess = *status.LastSuccess
		}
		if status.NextRefresh != nil {
			view.NextRefresh = *status.NextRefresh
		}
		for _, node := range status.Nodes {
			view.Nodes = append(view.Nodes, ui.SubscriptionNode{
				ID: node.ID, Name: node.Name, Health: node.Health, LatencyMS: node.LatencyMS, Checking: node.Checking,
			})
		}
		list = append(list, view)
	}
	return list
}

func (d uiDeps) TrafficSeries() []stats.Point {
	return d.daemon.TrafficSeries()
}

func (d uiDeps) RefreshSubscription(id, revision string) error {
	return d.daemon.RefreshSubscriptionIfCurrent(id, revision)
}

func (d uiDeps) CheckSubscription(source, node, revision string) error {
	return d.daemon.CheckSubscriptionIfCurrent(source, node, revision)
}

func pageRole(r *http.Request) ui.Role {
	switch api.RoleFrom(r.Context()) {
	case api.RoleView:
		return ui.RoleView
	case api.RoleManage:
		return ui.RoleManage
	default:
		return ui.RoleDeny
	}
}
