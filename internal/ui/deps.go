package ui

import (
	"context"
	"net/netip"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// Deps provides isolated configuration snapshots and management operations.
type Deps interface {
	Config() *model.Config
	PreviewSubscription(context.Context, subscription.Source) SetupPreview
	LANPrefix(iface string) (netip.Prefix, error)
	ConnectionRuntimeTags(cfg *model.Config) ([]string, error)
	ValidateConnection(ctx context.Context, cfg *model.Config, id string) error
	Apply(ctx context.Context, cfg *model.Config, revision string) error
	ApplySubscriptionPreview(ctx context.Context, cfg *model.Config, revision string, checked subscription.PreviewRef) error
	OverviewStatus() OverviewStatus
	Devices() []DiscoveredDevice
	Subscriptions() []AppliedSubscription
	ProviderRules() RoutingRules
	TrafficSeries() []stats.Point
	RefreshSubscription(id, revision string) error
	CheckSubscription(source, node, revision string) error
}

// DiscoveredDevice is an observation from the LAN snapshot. The applied
// config supplies any manual name, static address, and routing policy.
type DiscoveredDevice struct {
	MAC, IP, Name string
}

// RoutingRules describes the applied provider profile for the routing page.
// Large domain and address lists stay with the daemon.
type RoutingRules struct {
	Source, State           string
	HasProfile, GlobalProxy bool
	Rules                   []RoutingRule
}

// RoutingRule describes one switchable category or one list of literals.
type RoutingRule struct {
	Key, Action, Kind, Source, Unavailable string
	LiteralCount                           int
}

// SetupPreview contains display data from a checked subscription.
type SetupPreview struct {
	State      string
	Metadata   subscription.Metadata
	NodeCount  int
	NodeNames  []string
	Routing    *subscription.RoutingSummary
	RulesState string
	PreviewID  uint64
}

// OverviewStatus contains routing readiness, device counts and connection
// observations. Provider rules are exposed as counts and a state only.
type OverviewStatus struct {
	Ready                   bool
	Devices, ManagedDevices int
	Connections             map[string]ConnectionStatus
	RulesState              string
	RulesActive, RulesTotal int
}

// ConnectionStatus describes a routing target's static class, recent probe,
// and any selected failover member's ID and class.
type ConnectionStatus struct {
	Active             string
	Checked, Available bool
	Class, ActiveClass stats.TargetClass
	LatencyMS          int64
}

// AppliedSubscription exposes display metadata and the current catalog without
// the saved link, raw profiles, or fetch errors.
type AppliedSubscription struct {
	ID, State, ActiveNode, SwitchReason string
	RulesState                          string
	Metadata                            subscription.Metadata
	Nodes                               []SubscriptionNode
	Unavailable                         bool
	RulesWithheld                       bool
	BalanceEligible                     *int
	LastSuccess, NextRefresh            time.Time
	Refreshing                          bool
	Skipped                             int
	CheckingAll                         bool
}

// SubscriptionNode carries an opaque target ID and its latest probe state.
type SubscriptionNode struct {
	ID, Name, Health string
	LatencyMS        *int64
	Checking         bool
}
