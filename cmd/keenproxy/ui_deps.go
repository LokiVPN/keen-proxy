package main

import (
	"context"
	"net/http"
	"net/netip"

	"github.com/ordo-systems/keen-proxy/internal/api"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

type managementDaemon interface {
	api.Daemon
	PreviewSubscriptionDetails(context.Context, subscription.Source) daemon.SubscriptionPreviewDetails
	ApplyIfCurrent(context.Context, *model.Config, string) error
	ApplySubscriptionPreview(context.Context, *model.Config, string, subscription.PreviewRef) error
}

// uiDeps gives the pages display-only previews and revision-checked Apply.
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

func (d uiDeps) ApplySubscriptionPreview(ctx context.Context, cfg *model.Config, revision string, checked subscription.PreviewRef) error {
	ctx = daemon.WithActor(ctx, daemon.Actor{Who: "user"})
	return d.daemon.ApplySubscriptionPreview(ctx, cfg, revision, checked)
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
