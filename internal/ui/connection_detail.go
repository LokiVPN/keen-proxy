package ui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func (p pages) connectionDetailGet(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleManage && role != RoleView {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	p.renderConnectionDetail(w, r, http.StatusOK, p.deps.Config(), nil, "", nil)
}

// connectionDetailForm admits a native POST against the applied revision. The
// write or probe checks the same revision at the daemon synchronization point.
func (p pages) connectionDetailForm(w http.ResponseWriter, r *http.Request) (*model.Config, int) {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return nil, -1
	}
	r.Body = http.MaxBytesReader(w, r.Body, connectionsFormSize)
	if err := r.ParseForm(); err != nil {
		p.renderConnectionDetail(w, r, http.StatusBadRequest, p.deps.Config(), nil, "connections_invalid_form", nil)
		return nil, -1
	}
	cfg, message := p.checkRevision(r)
	if message != "" {
		p.renderConnectionDetail(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed", nil)
		return nil, -1
	}
	i := connectionIndex(cfg, connectionIDFromSegment(r.PathValue("id")))
	if i < 0 {
		p.notFound(w, r)
		return nil, -1
	}
	return cfg, i
}

func (p pages) connectionDetailSave(w http.ResponseWriter, r *http.Request) {
	cfg, i := p.connectionDetailForm(w, r)
	if cfg == nil {
		return
	}
	settings := p.readConnectionSettings(w, r, cfg, i)
	if settings == nil {
		return
	}
	draft := cfg.Clone()
	draft.Connections[i].Disabled, draft.Connections[i].Fallback = settings.Disabled, settings.Fallback
	if err := p.deps.ValidateConnectionSettings(r.Context(), draft); err != nil {
		p.renderConnectionDetail(w, r, http.StatusUnprocessableEntity, cfg, settings, "detail_invalid_runtime", nil)
		return
	}
	p.applyConnectionDetail(w, r, draft, settings, connectionDetailPath(settings.ID), "flash_saved")
}

// Check and Save submit the same settings. Check keeps this draft in the
// response and probes only the applied profile.
func (p pages) readConnectionSettings(w http.ResponseWriter, r *http.Request, cfg *model.Config, i int) *model.Connection {
	enabled := r.PostForm["enabled"]
	off := slices.Equal(enabled, []string{"0"})
	if !off && !slices.Equal(enabled, []string{"0", "1"}) {
		p.renderConnectionDetail(w, r, http.StatusBadRequest, cfg, nil, "overview_invalid_switch", nil)
		return nil
	}
	settings := cfg.Connections[i]
	settings.Disabled = off
	values := r.PostForm["fallback"]
	if len(values) != 1 {
		p.renderConnectionDetail(w, r, http.StatusUnprocessableEntity, cfg, &settings, "detail_invalid_reserve", nil)
		return nil
	}
	segment, err := url.PathUnescape(values[0])
	target := connectionIDFromSegment(segment)
	if err != nil || (target != "" && target != model.TargetDirect && connectionIndex(cfg, target) < 0) {
		p.renderConnectionDetail(w, r, http.StatusUnprocessableEntity, cfg, &settings, "detail_invalid_reserve", nil)
		return nil
	}
	settings.Fallback = target
	return &settings
}

func (p pages) connectionDetailDelete(w http.ResponseWriter, r *http.Request) {
	cfg, i := p.connectionDetailForm(w, r)
	if cfg == nil {
		return
	}
	id := cfg.Connections[i].ID
	refs := connectionReferences(cfg, id, localized(r))
	rawRefs, err := p.deps.ConnectionProfileReferences(r.Context(), cfg, id)
	refs = appendProfileReferences(refs, rawRefs, cfg, localized(r))
	if err != nil {
		p.renderConnectionDetail(w, r, http.StatusUnprocessableEntity, cfg, nil, "detail_reference_error", refs)
		return
	}
	if len(refs) > 0 {
		p.renderConnectionDetail(w, r, http.StatusConflict, cfg, nil, "detail_delete_referenced", refs)
		return
	}
	draft := cfg.Clone()
	draft.Connections = slices.Delete(draft.Connections, i, i+1)
	p.applyConnectionDetail(w, r, draft, nil, "/connections", "flash_detail_deleted")
}

func (p pages) connectionDetailProbe(w http.ResponseWriter, r *http.Request) {
	cfg, i := p.connectionDetailForm(w, r)
	if cfg == nil {
		return
	}
	settings := p.readConnectionSettings(w, r, cfg, i)
	if settings == nil {
		return
	}
	draft := *cfg
	draft.Connections = slices.Clone(cfg.Connections)
	draft.Connections[i] = *settings
	if err := p.deps.CheckConnectionSettings(r.Context(), &draft); err != nil {
		p.renderConnectionDetail(w, r, http.StatusUnprocessableEntity, cfg, settings, "detail_invalid_reserve", nil)
		return
	}
	conn := cfg.Connections[i]
	if conn.Disabled {
		p.renderConnectionDetail(w, r, http.StatusOK, cfg, settings, "detail_probe_disabled", nil)
		return
	}
	switch err := p.deps.CheckConnection(r.Context(), conn.ID, r.PostForm.Get("rev")); {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderConnectionDetail(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed", nil)
	case err != nil:
		p.renderConnectionDetail(w, r, http.StatusServiceUnavailable, cfg, settings, "detail_probe_error", nil)
	default:
		p.renderConnectionDetail(w, r, http.StatusOK, cfg, settings, "flash_detail_checked", nil)
	}
}

func (p pages) applyConnectionDetail(w http.ResponseWriter, r *http.Request, draft *model.Config, settings *model.Connection, next, flash string) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	revision := r.PostForm.Get("rev")
	err := p.deps.Apply(ctx, draft, revision)
	if err == nil {
		redirectWithFlash(w, r, next, flash)
		return
	}
	current := p.deps.Config()
	var unsaved *model.AppliedUnsavedError
	switch {
	case errors.As(err, &unsaved):
		p.renderConnectionDetail(w, r, http.StatusInternalServerError, current, nil, "apply_not_saved", nil)
	case errors.Is(err, model.ErrConfigChanged), Revision(current) != revision:
		p.renderConnectionDetail(w, r, http.StatusConflict, current, nil, "revision_changed", nil)
	default:
		p.renderConnectionDetail(w, r, http.StatusUnprocessableEntity, current, settings, "overview_apply_error", nil)
	}
}

// Fragments only read observations for a saved ID. In particular the health
// refresh does not initiate a probe, and no fragment can reveal a profile.
func (p pages) connectionDetailFragment(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if role := p.role(r); role != RoleManage && role != RoleView {
			p.opts.AccessError(w, r, http.StatusForbidden)
			return
		}
		id := connectionIDFromSegment(r.PathValue("id"))
		health, found := p.deps.ConnectionHealth(id)
		if !found {
			http.NotFound(w, r)
			return
		}
		data := p.opts.pageData(r)
		if health.TrafficGroup && name != "connection-health" {
			data.ConnectionTraffic = p.detailTrafficMembers(r.Context(), p.deps.Config(), id, health.TrafficMembers, data.Text)
			render(w, r, http.StatusOK, "connection-traffic-members", data)
			return
		}
		switch name {
		case "connection-health":
			data.ConnectionHealth = detailHealth(health, data.Text)
		case "overview-traffic":
			_, series := p.deps.ConnectionTraffic(id)
			data.Traffic = trafficChart(series, time.Now(), data.Lang, "detail_chart_label")
		case "connection-hosts":
			data.ConnectionHosts = p.detailHosts(id, r.URL.Query().Get("hosts") == "all", data.Lang)
		}
		render(w, r, http.StatusOK, name, data)
	}
}
