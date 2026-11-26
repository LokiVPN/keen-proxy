package ui

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/update"
)

// Deps provides isolated configuration snapshots and management operations.
type Deps interface {
	Config() *model.Config
	PreviewSubscription(context.Context, subscription.Source) SetupPreview
	LANPrefix(iface string) (netip.Prefix, error)
	ConnectionRuntimeTags(cfg *model.Config) ([]string, error)
	ValidateConnection(ctx context.Context, cfg *model.Config, id string) error
	ConnectionReserveTargets(ctx context.Context, cfg *model.Config, id string) []string
	CheckConnectionSettings(ctx context.Context, cfg *model.Config) error
	ValidateConnectionSettings(ctx context.Context, cfg *model.Config) error
	Apply(ctx context.Context, cfg *model.Config, revision string) error
	// ApplyUnlessRulesWithheld rechecks the revision and source at commit.
	ApplyUnlessRulesWithheld(ctx context.Context, cfg *model.Config, revision, source string) error
	ApplySubscriptionPreview(ctx context.Context, cfg *model.Config, revision string, checked subscription.PreviewRef) error
	OverviewStatus() OverviewStatus
	Devices() []DiscoveredDevice
	Subscriptions() []AppliedSubscription
	ProviderRules() RoutingRules
	TrafficSeries() []stats.Point
	RefreshSubscription(id, revision string) error
	CheckSubscription(source, node, revision string) error
	ConnectionHealth(id string) (ConnectionHealth, bool)
	ConnectionGroupMembers(ctx context.Context, conn model.Connection) []string
	ConnectionTraffic(id string) (active int, series []stats.Point)
	ConnectionHosts(id string, limit int) ([]stats.Host, int)
	CheckConnection(ctx context.Context, id, revision string) error
	ConnectionProfileReferences(ctx context.Context, cfg *model.Config, id string) ([]string, error)
	SubscriptionProfileReferences(ctx context.Context, cfg *model.Config, id string) ([]string, error)
	DiagnosticStatus(context.Context) DiagnosticStatus
	DiagnosticNode(target string) DiagnosticNode
	CheckDiagnosticTarget(ctx context.Context, target, revision string) (DiagnosticCheckResult, error)
	SupportBundle(http.ResponseWriter, *http.Request)
	UpdateStatus() update.Status
	CheckUpdates(context.Context)
	StartUpdate(target string, rollback bool) error
	SaveUpdatePreferences(update.Preferences, string) error
}

// DiagnosticStatus projects runtime and build facts without listener
// addresses, profile settings, or error details.
type DiagnosticStatus struct {
	Started, AppliedAt          time.Time
	Core, Firewall, DNS, Paused bool
	Mode, GeoBuilt              string
	GeoLoaded                   bool
	Restorations                int
	System                      stats.System
	Build                       string
}

// DiagnosticProbe carries only the outcome of an allowlisted probe.
type DiagnosticProbe struct {
	Kind      string
	OK        bool
	LatencyMS int64
}

// DiagnosticNode holds protected display data for the node and subscription
// at check time. A node name withheld for privacy is empty.
type DiagnosticNode struct {
	Name, SubscriptionTitle string
	Position                int
}

// DiagnosticCheckResult records the selected route and any probes it ran.
type DiagnosticCheckResult struct {
	Probes                          []DiagnosticProbe
	Node                            DiagnosticNode
	CheckedAt                       time.Time
	Group, GroupName, Leaf, Reserve string
	SkippedVPN                      bool
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
	HomeTargets             []string
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

// ConnectionHealth is the saved profile's reachability and its routing
// target's static class. The probe result never contains a URL or raw error.
type ConnectionHealth struct {
	Disabled, Available, HTTPS bool
	Checked                    time.Time
	LatencyMS                  int64
	Class                      stats.TargetClass
	TrafficGroup               bool
	TrafficMembers             []string
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
