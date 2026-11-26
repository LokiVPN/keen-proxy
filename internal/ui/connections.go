package ui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
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

	checks, refreshes := r.PostForm["check"], r.PostForm["refresh"]
	r.PostForm.Del("check")
	r.PostForm.Del("refresh")
	draft := cfg.Clone()
	if problem := updateConnections(draft, r.PostForm); problem != "" {
		p.renderConnections(w, r, http.StatusUnprocessableEntity, cfg, nil, problem)
		return
	}
	revision := r.PostForm.Get("rev")
	switch {
	case len(checks)+len(refreshes) > 1:
		p.renderConnections(w, r, http.StatusBadRequest, cfg, draft, "connections_invalid_form")
		return
	case len(checks) == 1:
		p.connectionsCheck(w, r, cfg, draft, checks[0], revision)
		return
	case len(refreshes) == 1:
		p.connectionsRefresh(w, r, cfg, draft, refreshes[0], revision)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
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
			segment, err := url.PathUnescape(values[0])
			target := connectionIDFromSegment(segment)
			if err != nil || !slices.Contains(targets, target) {
				return "connections_invalid_reserve"
			}
			source.Fallback = target
		}
	}
	for i := range draft.Connections {
		conn := &draft.Connections[i]
		switch values := form[connectionEnabledField(conn.ID)]; {
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

// connectionsCheck queues the saved node check and renders the submitted
// settings as a draft. Only Save applies the form's reserve and switch edits.
func (p pages) connectionsCheck(w http.ResponseWriter, r *http.Request, cfg, draft *model.Config, check, revision string) {
	source, node, found := strings.Cut(check, ":")
	if !found || source == "" {
		p.renderConnections(w, r, http.StatusBadRequest, cfg, draft, "connections_invalid_form")
		return
	}
	err := p.deps.CheckSubscription(source, node, revision)
	switch {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderConnections(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed")
	case err != nil:
		p.renderConnections(w, r, http.StatusUnprocessableEntity, cfg, draft, "connections_check_error")
	default:
		p.renderConnections(w, r, http.StatusOK, cfg, draft, "flash_connections_check")
	}
}

// connectionsRefresh queues a fetch for one applied source and preserves any
// edits on the form for a later Save.
func (p pages) connectionsRefresh(w http.ResponseWriter, r *http.Request, cfg, draft *model.Config, source, revision string) {
	if !slices.ContainsFunc(cfg.Subscriptions, func(sub subscription.Source) bool { return sub.ID == source }) {
		p.renderConnections(w, r, http.StatusBadRequest, cfg, draft, "connections_invalid_form")
		return
	}
	switch err := p.deps.RefreshSubscription(source, revision); {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderConnections(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed")
	case err != nil:
		p.renderConnections(w, r, http.StatusServiceUnavailable, cfg, draft, "overview_refresh_error")
	default:
		p.renderConnections(w, r, http.StatusOK, cfg, draft, "flash_subscription_refresh")
	}
}

// connectionsFragment refreshes observations without touching any form values
// or doing network work. The settings and revision live outside the fragment.
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
	titles := subscriptionTitlesFor(nil, subs)
	data.SubscriptionNodes = connectionNodes(subs[i], titles, role == RoleView, time.Now(), data.Text)
	render(w, r, http.StatusOK, "connections-nodes-fragment", data)
}

func (p pages) renderConnections(w http.ResponseWriter, r *http.Request, status int, cfg, draft *model.Config, messageKey string) {
	p.renderConnectionsResult(w, r, status, cfg, draft, localized(r)[messageKey], nil)
}

func (p pages) renderConnectionsResult(w http.ResponseWriter, r *http.Request, status int, cfg, draft *model.Config, message string, refs []connectionReference) {
	data := p.opts.pageData(r)
	data.SignedIn = true
	data.ViewOnly = p.role(r) == RoleView
	data.Title = data.Text["nav_connections"]
	data.ActiveTab = "/connections"
	if r.Method == http.MethodPost && status == http.StatusOK {
		data.Flash = message
	} else {
		data.Message = message
		data.Flash = takeFlash(w, r, data.Text)
	}
	if cfg != nil {
		data.Connections = connectionsView(cfg, draft, p.deps.Subscriptions(), p.deps.OverviewStatus().Connections, data.ViewOnly, data.Text)
		data.Connections.References = refs
	}
	render(w, r, status, "connections", data)
}
