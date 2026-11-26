package ui

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	setupSourceID = "main"
	setupFormSize = 16 << 10
	setupPath     = "/setup"
)

// setupFlow binds a checked draft to one canonical action, including the
// source ID for replacements. The legacy setup route retains its behavior.
type setupFlow struct {
	path      string
	replaceID string
}

func setupFlowFor(r *http.Request) setupFlow {
	if id := r.PathValue("id"); id != "" {
		return setupFlow{path: subscriptionPath(id) + "/replace", replaceID: id}
	}
	if strings.HasPrefix(r.URL.Path, subscriptionPathPrefix) {
		return setupFlow{path: subscriptionNewPath}
	}
	return setupFlow{path: setupPath}
}

func (f setupFlow) replacement(cfg *model.Config) int {
	if f.replaceID != "" {
		return subscriptionIndex(cfg, f.replaceID)
	}
	if f.path == setupPath && len(cfg.Subscriptions) > 0 {
		return 0
	}
	return -1
}

func (f setupFlow) initialRouting(cfg *model.Config) bool {
	return f.path == setupPath && setupInitialRouting(cfg)
}

// setupInitialRouting identifies the only setup mode that creates a LAN policy.
func setupInitialRouting(cfg *model.Config) bool {
	return len(cfg.Subscriptions) == 0 && len(cfg.Networks) == 0
}

func (p pages) setupGet(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleView && role != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	cfg := p.deps.Config()
	if id := r.PathValue("id"); cfg != nil && id != "" && subscriptionIndex(cfg, id) == -1 {
		p.notFound(w, r)
		return
	}
	p.renderSetup(w, r, http.StatusOK, cfg, setupPage{})
}

func (p pages) setupCheck(w http.ResponseWriter, r *http.Request) {
	cfg := p.setupRevision(w, r)
	if cfg == nil {
		return
	}
	text := localized(r)
	flow := setupFlowFor(r)
	source := subscription.Source{ID: setupSourceID, SendHWID: true}
	if i := flow.replacement(cfg); i >= 0 {
		source.ID = cfg.Subscriptions[i].ID
	}
	if urls := r.PostForm["url"]; len(urls) == 1 {
		source.URL = strings.TrimSpace(urls[0])
	}
	if subscription.ValidateSource(source) != nil {
		p.renderSetup(w, r, http.StatusBadRequest, cfg, setupPage{Input: source.URL, Error: text["setup_invalid_url"]})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if flow.path == subscriptionNewPath {
		id, err := p.newSubscriptionID(ctx, cfg)
		if err != nil {
			p.renderSetup(w, r, http.StatusUnprocessableEntity, cfg, setupPage{Error: text["setup_unavailable"]})
			return
		}
		source.ID = id
	}

	preview := p.deps.PreviewSubscription(ctx, source)
	now := time.Now()
	expiry := setupExpiry(preview.Metadata.Usage)
	result := setupResultFor(preview, now, expiry, language(r))
	page := setupPage{Result: result}
	switch {
	case result == nil:
		page.Input, page.Error = source.URL, text["setup_unreachable"]
	case !result.Active:
		page.Input = source.URL
	case preview.PreviewID == 0:
		page.Result, page.Error = nil, text["setup_check_again"]
	default:
		rules := cfg.ActiveProviderRules()
		page.EvaluateRules = flow.initialRouting(cfg) || (rules != nil && rules.Source == source.ID)
		deadline := now.Add(setupDraftLifetime)
		if !expiry.IsZero() && expiry.Before(deadline) {
			deadline = expiry
		}
		result.Token = p.setupDrafts.save(setupDraft{
			preview: subscription.PreviewRef{Source: source, ID: preview.PreviewID},
			rev:     Revision(cfg), user: p.opts.requestUser(r), path: flow.path, expires: deadline,
		}, now)
	}
	p.renderSetup(w, r, http.StatusOK, cfg, page)
}

func (p pages) setupEnable(w http.ResponseWriter, r *http.Request) {
	cfg := p.setupRevision(w, r)
	if cfg == nil {
		return
	}
	text := localized(r)
	flow := setupFlowFor(r)
	rev := Revision(cfg)
	token := r.PostForm["preview"]
	var checked subscription.PreviewRef
	if len(token) == 1 {
		checked = p.setupDrafts.take(token[0], rev, p.opts.requestUser(r), flow.path, time.Now())
	}
	if checked.ID == 0 {
		p.renderSetup(w, r, http.StatusConflict, cfg, setupPage{Error: text["setup_check_again"]})
		return
	}
	source := checked.Source
	if i := flow.replacement(cfg); i >= 0 {
		cfg.Subscriptions[i].URL = source.URL
		cfg.Subscriptions[i].SendHWID = source.SendHWID
	} else {
		if flow.initialRouting(cfg) {
			lan, err := p.deps.LANPrefix(cfg.LAN.Interface)
			if err != nil || !lan.IsValid() {
				p.renderSetup(w, r, http.StatusUnprocessableEntity, cfg, setupPage{Error: text["setup_no_lan"]})
				return
			}
			cfg.RouteHomeThroughSubscription(source.ID, lan)
		}
		cfg.Subscriptions = append(cfg.Subscriptions, source)
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var unsaved *model.AppliedUnsavedError
	switch err := p.deps.ApplySubscriptionPreview(ctx, cfg, rev, checked); {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderSetup(w, r, http.StatusConflict, p.deps.Config(), setupPage{Error: text["revision_changed"]})
	case errors.Is(err, subscription.ErrPreviewChanged):
		p.renderSetup(w, r, http.StatusConflict, p.deps.Config(), setupPage{Error: text["setup_check_again"]})
	case errors.As(err, &unsaved):
		p.renderSetup(w, r, http.StatusInternalServerError, p.deps.Config(), setupPage{Warning: text["apply_not_saved"]})
	case err != nil:
		p.renderSetup(w, r, http.StatusUnprocessableEntity, p.deps.Config(), setupPage{Error: text["setup_apply_error"]})
	default:
		next := "/"
		if flow.path != setupPath {
			next = "/connections"
		}
		redirectWithFlash(w, r, next, "flash_saved")
	}
}

// setupRevision checks role and revision before any provider or Apply work.
func (p pages) setupRevision(w http.ResponseWriter, r *http.Request) *model.Config {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, setupFormSize)
	cfg, message := p.checkRevision(r)
	if message != "" {
		p.renderSetup(w, r, http.StatusConflict, p.deps.Config(), setupPage{Error: message})
	} else if id := r.PathValue("id"); id != "" && subscriptionIndex(cfg, id) == -1 {
		p.notFound(w, r)
		return nil
	}
	return cfg
}
