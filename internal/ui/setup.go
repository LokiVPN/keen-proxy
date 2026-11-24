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
)

// setupInitialRouting identifies the only setup mode that creates a LAN policy.
func setupInitialRouting(cfg *model.Config) bool {
	return len(cfg.Subscriptions) == 0 && len(cfg.Networks) == 0
}

func (p pages) setupGet(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleView && role != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	p.renderSetup(w, r, http.StatusOK, p.deps.Config(), setupPage{})
}

func (p pages) setupCheck(w http.ResponseWriter, r *http.Request) {
	cfg := p.setupRevision(w, r)
	if cfg == nil {
		return
	}
	text := localized(r)
	source := subscription.Source{ID: setupSourceID, SendHWID: true}
	if len(cfg.Subscriptions) != 0 {
		source.ID = cfg.Subscriptions[0].ID
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
		page.EvaluateRules = setupInitialRouting(cfg) || (cfg.ProviderRules != nil && cfg.ProviderRules.Source == source.ID)
		deadline := now.Add(setupDraftLifetime)
		if !expiry.IsZero() && expiry.Before(deadline) {
			deadline = expiry
		}
		result.Token = p.setupDrafts.save(setupDraft{
			preview: subscription.PreviewRef{Source: source, ID: preview.PreviewID},
			rev:     Revision(cfg), user: p.setupUser(r), expires: deadline,
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
	rev := Revision(cfg)
	token := r.PostForm["preview"]
	var checked subscription.PreviewRef
	if len(token) == 1 {
		checked = p.setupDrafts.take(token[0], rev, p.setupUser(r), time.Now())
	}
	if checked.ID == 0 {
		p.renderSetup(w, r, http.StatusConflict, cfg, setupPage{Error: text["setup_check_again"]})
		return
	}
	source := checked.Source
	if len(cfg.Subscriptions) == 0 {
		if setupInitialRouting(cfg) {
			lan, err := p.deps.LANPrefix(cfg.LAN.Interface)
			if err != nil || !lan.IsValid() {
				p.renderSetup(w, r, http.StatusUnprocessableEntity, cfg, setupPage{Error: text["setup_no_lan"]})
				return
			}
			cfg.RouteHomeThroughSubscription(source.ID, lan)
		}
		cfg.Subscriptions = []subscription.Source{source}
	} else {
		cfg.Subscriptions[0].URL = source.URL
		cfg.Subscriptions[0].SendHWID = source.SendHWID
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
		redirectWithFlash(w, r, "/", "flash_saved")
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
	}
	return cfg
}

func (p pages) setupUser(r *http.Request) string {
	if p.opts.User != nil {
		return p.opts.User(r)
	}
	return ""
}
