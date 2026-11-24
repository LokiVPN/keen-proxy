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
	Apply(ctx context.Context, cfg *model.Config, revision string) error
	ApplySubscriptionPreview(ctx context.Context, cfg *model.Config, revision string, checked subscription.PreviewRef) error
	OverviewStatus() OverviewStatus
	Subscriptions() []AppliedSubscription
	TrafficSeries() []stats.Point
	RefreshSubscription(id, revision string) error
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
	Devices, VPNDevices     int
	Connections             map[string]ConnectionStatus
	RulesState              string
	RulesActive, RulesTotal int
}

// ConnectionStatus describes a manual connection's probe and any selected reserve.
type ConnectionStatus struct {
	Active             string
	Checked, Available bool
	LatencyMS          int64
}

// AppliedSubscription exposes display metadata and the current catalog without
// the saved link, raw profiles, or fetch errors.
type AppliedSubscription struct {
	ID, State, ActiveNode, SwitchReason string
	Metadata                            subscription.Metadata
	Nodes                               []SubscriptionNode
	Unavailable                         bool
	BalanceEligible                     *int
	LastSuccess, NextRefresh            time.Time
	Refreshing                          bool
}

// SubscriptionNode carries an opaque target ID and its latest probe state.
type SubscriptionNode struct {
	ID, Name, Health string
	LatencyMS        *int64
}
