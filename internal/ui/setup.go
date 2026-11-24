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
	default:
		deadline := now.Add(setupDraftLifetime)
		if !expiry.IsZero() && expiry.Before(deadline) {
			deadline = expiry
		}
		result.Token = p.setupDrafts.save(setupDraft{
			source: source, rev: Revision(cfg), user: p.setupUser(r), expires: deadline,
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
	var source subscription.Source
	if len(token) == 1 {
		source = p.setupDrafts.take(token[0], rev, p.setupUser(r), time.Now())
	}
	if source.ID == "" {
		p.renderSetup(w, r, http.StatusConflict, cfg, setupPage{Error: text["setup_check_again"]})
		return
	}
	if len(cfg.Subscriptions) == 0 {
		lan, err := p.deps.LANPrefix(cfg.LAN.Interface)
		if err != nil || !lan.IsValid() {
			p.renderSetup(w, r, http.StatusUnprocessableEntity, cfg, setupPage{Error: text["setup_no_lan"]})
			return
		}
		cfg.Subscriptions = []subscription.Source{source}
		cfg.RouteHomeThroughSubscription(source.ID, lan)
	} else {
		cfg.Subscriptions[0].URL = source.URL
		cfg.Subscriptions[0].SendHWID = source.SendHWID
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	switch err := p.deps.Apply(ctx, cfg, rev); {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderSetup(w, r, http.StatusConflict, p.deps.Config(), setupPage{Error: text["revision_changed"]})
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
