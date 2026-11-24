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

const connectionsFormSize = 1 << 20

func (p pages) connectionsGet(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleManage && role != RoleView {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	p.renderConnections(w, r, http.StatusOK, p.deps.Config(), nil, "")
}

func (p pages) connectionsPost(w http.ResponseWriter, r *http.Request) {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, connectionsFormSize)
	if err := r.ParseForm(); err != nil {
		p.renderConnections(w, r, http.StatusBadRequest, p.deps.Config(), nil, "connections_invalid_form")
		return
	}
	cfg, message := p.checkRevision(r)
	if message != "" {
		p.renderConnections(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed")
		return
	}

	draft := cfg.Clone()
	if problem := updateConnections(draft, r.PostForm); problem != "" {
		p.renderConnections(w, r, http.StatusUnprocessableEntity, cfg, nil, problem)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	revision := r.PostForm.Get("rev")
	err := p.deps.Apply(ctx, draft, revision)
	if err == nil {
		redirectWithFlash(w, r, "/connections", "flash_saved")
		return
	}
	current := p.deps.Config()
	var unsaved *model.AppliedUnsavedError
	switch {
	case errors.As(err, &unsaved):
		p.renderConnections(w, r, http.StatusInternalServerError, current, nil, "apply_not_saved")
	case errors.Is(err, model.ErrConfigChanged), Revision(current) != revision:
		p.renderConnections(w, r, http.StatusConflict, current, nil, "revision_changed")
	default:
		p.renderConnections(w, r, http.StatusUnprocessableEntity, current, draft, "overview_apply_error")
	}
}

// updateConnections changes only the fields represented by the full Save form.
// Each switch has an explicit off value so a missing control cannot turn it off.
func updateConnections(draft *model.Config, form url.Values) string {
	if len(form) != 1+len(draft.Connections)+len(draft.Subscriptions) {
		return "connections_invalid_form"
	}
	if len(draft.Subscriptions) > 0 {
		targets := draft.SubscriptionFallbackTargets()
		for i := range draft.Subscriptions {
			source := &draft.Subscriptions[i]
			values := form["fallback."+source.ID]
			if len(values) != 1 {
				return "connections_invalid_reserve"
			}
			// An existing unset reserve can stay unset. An explicit block
			// is different: the automatic selector can switch to it on failure.
			if values[0] == "" && source.Fallback == "" {
				continue
			}
			if !slices.Contains(targets, values[0]) {
				return "connections_invalid_reserve"
			}
			source.Fallback = values[0]
		}
	}
	for i := range draft.Connections {
		conn := &draft.Connections[i]
		switch values := form["enabled."+conn.ID]; {
		case slices.Equal(values, []string{"0"}):
			conn.Disabled = true
		case slices.Equal(values, []string{"0", "1"}):
			conn.Disabled = false
		default:
			return "connections_invalid_form"
		}
	}
	return ""
}

// connectionsCheck queues an existing daemon check without applying settings.
func (p pages) connectionsCheck(w http.ResponseWriter, r *http.Request) {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, overviewFormSize)
	if err := r.ParseForm(); err != nil || len(r.PostForm["node"]) != 1 {
		p.renderConnections(w, r, http.StatusBadRequest, p.deps.Config(), nil, "connections_invalid_form")
		return
	}
	revs := r.PostForm["rev"]
	if len(revs) != 1 || revs[0] == "" {
		p.renderConnections(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed")
		return
	}
	err := p.deps.CheckSubscription(r.PathValue("source"), r.PostForm.Get("node"), revs[0])
	switch {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderConnections(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed")
	case err != nil:
		p.renderConnections(w, r, http.StatusUnprocessableEntity, p.deps.Config(), nil, "connections_check_error")
	default:
		redirectWithFlash(w, r, "/connections", "flash_connections_check")
	}
}

// connectionsFragment refreshes observations without touching any form values
// or doing network work. The check form outside the fragment keeps its revision.
func (p pages) connectionsFragment(w http.ResponseWriter, r *http.Request) {
	role := p.role(r)
	if role != RoleManage && role != RoleView {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	subs := p.deps.Subscriptions()
	id := r.PathValue("source")
	i := slices.IndexFunc(subs, func(sub AppliedSubscription) bool { return sub.ID == id })
	if i == -1 {
		http.NotFound(w, r)
		return
	}
	data := p.opts.pageData(r)
	data.SubscriptionNodes = connectionNodes(subs[i], role == RoleView, time.Now(), data.Text)
	render(w, r, http.StatusOK, "connections-nodes-fragment", data)
}

func (p pages) renderConnections(w http.ResponseWriter, r *http.Request, status int, cfg, draft *model.Config, message string) {
	data := p.opts.pageData(r)
	data.SignedIn = true
	data.ViewOnly = p.role(r) == RoleView
	data.Title = data.Text["nav_connections"]
	data.ActiveTab = "/connections"
	data.Message = data.Text[message]
	data.Flash = takeFlash(w, r, data.Text)
	if cfg != nil {
		data.Connections = connectionsView(cfg, draft, p.deps.Subscriptions(), p.deps.OverviewStatus().Connections, data.ViewOnly, data.Text)
	}
	render(w, r, status, "connections", data)
}
