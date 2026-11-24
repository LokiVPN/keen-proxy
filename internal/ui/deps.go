package ui

import (
	"context"
	"net/netip"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// Deps provides isolated configuration snapshots and management operations.
type Deps interface {
	Config() *model.Config
	PreviewSubscription(context.Context, subscription.Source) SetupPreview
	LANPrefix(iface string) (netip.Prefix, error)
	Apply(ctx context.Context, cfg *model.Config, revision string) error
	ApplySubscriptionPreview(ctx context.Context, cfg *model.Config, revision string, checked subscription.PreviewRef) error
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
