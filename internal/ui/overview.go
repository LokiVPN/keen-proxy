package ui

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

const overviewFormSize = 4 << 10

func (p pages) home(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleView && role != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	cfg := p.deps.Config()
	if cfg != nil && setupInitialRouting(cfg) && len(cfg.Connections) == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	p.renderOverview(w, r, http.StatusOK, cfg, "")
}

func (p pages) overviewPause(w http.ResponseWriter, r *http.Request) {
	cfg := p.overviewForm(w, r)
	if cfg == nil {
		return
	}
	enabled := r.PostForm["enabled"]
	if len(enabled) > 1 || (len(enabled) == 1 && enabled[0] != "1") {
		p.renderOverview(w, r, http.StatusBadRequest, cfg, "overview_invalid_switch")
		return
	}
	cfg.Paused = len(enabled) == 0
	p.applyOverview(w, r, cfg)
}

func (p pages) overviewConnection(w http.ResponseWriter, r *http.Request) {
	cfg := p.overviewForm(w, r)
	if cfg == nil {
		return
	}
	network := cfg.HomeNetwork()
	target := r.PostForm["target"]
	if network == nil || len(target) != 1 ||
		!selectableConnection(connectionOptions(cfg, p.deps.Subscriptions(), nil, localized(r)), target[0]) {
		p.renderOverview(w, r, http.StatusUnprocessableEntity, cfg, "overview_invalid_connection")
		return
	}
	// Full-VPN mode and the provider mode's VPN choice both store the main
	// target as the split default. Empty, direct and profile are independent.
	if routingRemainingChoice(network) == routingVPN {
		if target[0] == model.DefaultProfile {
			p.renderOverview(w, r, http.StatusUnprocessableEntity, cfg, "routing_main_profile_id")
			return
		}
		network.Default = target[0]
	}
	vpn := routingOwnGroups(cfg, ownVPNGroup, network.Target)
	if network.Mode != model.ModeFull && len(vpn.groups) == 1 && !vpn.readOnly() {
		state := routingState{class: connectionClass(network.Target, p.deps.OverviewStatus().Connections)}
		if state.canUseVPN() {
			vpn.groups[0].Target = target[0]
		}
	}
	network.Target = target[0]
	p.applyOverview(w, r, cfg)
}

func (p pages) overviewRefresh(w http.ResponseWriter, r *http.Request) {
	cfg := p.overviewForm(w, r)
	if cfg == nil {
		return
	}
	if len(cfg.Subscriptions) == 0 {
		p.renderOverview(w, r, http.StatusUnprocessableEntity, cfg, "overview_no_subscription")
		return
	}
	sources := r.PostForm["source"]
	if len(sources) != 1 || subscriptionIndex(cfg, sources[0]) < 0 {
		p.renderOverview(w, r, http.StatusUnprocessableEntity, cfg, "subscription_choose_configured")
		return
	}
	err := p.deps.RefreshSubscription(sources[0], r.PostForm.Get("rev"))
	switch {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderOverview(w, r, http.StatusConflict, p.deps.Config(), "revision_changed")
	case err != nil:
		p.renderOverview(w, r, http.StatusServiceUnavailable, p.deps.Config(), "overview_refresh_error")
	default:
		redirectWithFlash(w, r, "/", "flash_subscription_refresh")
	}
}

// overviewForm refuses stale forms before doing work. The daemon checks the
// same revision again when it commits an Apply or queues the refresh.
func (p pages) overviewForm(w http.ResponseWriter, r *http.Request) *model.Config {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, overviewFormSize)
	cfg, message := p.checkRevision(r)
	if message != "" {
		p.renderOverview(w, r, http.StatusConflict, p.deps.Config(), "revision_changed")
	}
	return cfg
}

func (p pages) applyOverview(w http.ResponseWriter, r *http.Request, cfg *model.Config) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var unsaved *model.AppliedUnsavedError
	switch err := p.deps.Apply(ctx, cfg, r.PostForm.Get("rev")); {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderOverview(w, r, http.StatusConflict, p.deps.Config(), "revision_changed")
	case errors.As(err, &unsaved):
		p.renderOverview(w, r, http.StatusInternalServerError, p.deps.Config(), "apply_not_saved")
	case err != nil:
		p.renderOverview(w, r, http.StatusUnprocessableEntity, p.deps.Config(), "overview_apply_error")
	default:
		redirectWithFlash(w, r, "/", "flash_saved")
	}
}

func (p pages) trafficFragment(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleView && role != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	data := p.opts.pageData(r)
	data.Traffic = overviewTraffic(p.deps.TrafficSeries(), time.Now(), data.Lang)
	render(w, r, http.StatusOK, "overview-traffic", data)
}
