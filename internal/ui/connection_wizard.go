package ui

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/connectionimport"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	wizardCheckBody = connectionimport.MaxSize + (16 << 10)
	wizardSaveBody  = 16 << 10
)

func (p pages) connectionWizardGet(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleManage && role != RoleView {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	loc := wizardLocationFor(r.URL.Query())
	cfg := p.deps.Config()
	if cfg == nil {
		p.wizardError(w, r, http.StatusServiceUnavailable, nil, loc, "setup_unavailable")
		return
	}
	if segment := r.PathValue("id"); segment != "" {
		loc.replace = connectionIDFromSegment(segment)
		if loc.replace == "" || connectionIndex(cfg, loc.replace) < 0 {
			p.notFound(w, r)
			return
		}
	}
	p.renderConnectionWizard(w, r, http.StatusOK, cfg, loc, connectionWizardPage{})
}

func (p pages) connectionWizardCheck(w http.ResponseWriter, r *http.Request) {
	cfg, loc := p.wizardForm(w, r, wizardCheckBody)
	if cfg == nil {
		return
	}
	if loc.replace != "" && connectionIndex(cfg, loc.replace) < 0 {
		p.notFound(w, r)
		return
	}
	if r.PostForm.Has("choice") {
		p.chooseWizardProfile(w, r, cfg, loc)
		return
	}
	candidates, err := wizardImport(r)
	if err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, connectionimport.ErrTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		p.renderConnectionWizard(w, r, status, cfg, loc, connectionWizardPage{Error: wizardImportError(localized(r), err)})
		return
	}
	draft := connectionDraft{
		rev: r.PostForm.Get("rev"), location: loc, candidates: candidates,
		expires: time.Now().Add(connectionDraftLifetime),
	}
	if len(candidates) > 1 {
		draft.session = p.wizardSession(w, r, true)
		p.renderWizardChoices(w, r, http.StatusOK, cfg, draft, "")
		return
	}
	p.reviewWizardProfile(w, r, cfg, draft)
}

func wizardImport(r *http.Request) ([]connectionimport.Draft, error) {
	if len(r.PostForm["method"]) != 1 {
		return nil, connectionimport.ErrInvalid
	}
	switch r.PostForm.Get("method") {
	case "paste":
		if profile := r.PostForm["profile"]; len(profile) == 1 {
			return connectionimport.Parse(profile[0], "")
		}
	case "file":
		if r.MultipartForm != nil && len(r.MultipartForm.File["file"]) == 1 {
			return readWizardFile(r)
		}
	case "manual":
		draft, err := connectionimport.Manual(r.PostForm)
		if err != nil {
			return nil, err
		}
		return []connectionimport.Draft{draft}, nil
	}
	return nil, connectionimport.ErrInvalid
}

func readWizardFile(r *http.Request) ([]connectionimport.Draft, error) {
	header := r.MultipartForm.File["file"][0]
	if header.Size > connectionimport.MaxSize {
		return nil, connectionimport.ErrTooLarge
	}
	file, err := header.Open()
	if err != nil {
		return nil, connectionimport.ErrInvalid
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, connectionimport.MaxSize+1))
	if err != nil {
		return nil, connectionimport.ErrInvalid
	}
	return connectionimport.Parse(string(data), header.Filename)
}

func (p pages) chooseWizardProfile(w http.ResponseWriter, r *http.Request, cfg *model.Config, loc wizardLocation) {
	draft, ok := p.takeWizardDraft(w, r, true)
	if !ok {
		p.wizardError(w, r, http.StatusConflict, cfg, loc, "wizard_check_again")
		return
	}
	choice, err := strconv.Atoi(r.PostForm.Get("choice"))
	if err != nil || len(r.PostForm["choice"]) != 1 || choice < 0 || choice >= len(draft.candidates) {
		p.renderWizardChoices(w, r, http.StatusUnprocessableEntity, cfg, draft, "wizard_choose_required")
		return
	}
	draft.candidates = []connectionimport.Draft{draft.candidates[choice]}
	p.reviewWizardProfile(w, r, cfg, draft)
}

func (p pages) reviewWizardProfile(w http.ResponseWriter, r *http.Request, cfg *model.Config, draft connectionDraft) {
	profile := draft.candidates[0]
	name := wizardSuggestedName(profile)
	id := draft.location.replace
	if id == "" {
		id = availableWizardID(cfg, name)
	} else if i := connectionIndex(cfg, id); i >= 0 {
		name = cmp.Or(cfg.Connections[i].Name, id)
	} else {
		p.notFound(w, r)
		return
	}
	candidate := withWizardConnection(cfg, profile.Connection, draft.location.replace, id, name)
	if err := p.deps.ValidateConnection(r.Context(), candidate, id); err != nil {
		p.wizardError(w, r, http.StatusUnprocessableEntity, cfg, draft.location, "wizard_validation")
		return
	}
	draft.session = p.wizardSession(w, r, true)
	p.renderWizardReview(w, r, http.StatusOK, cfg, draft, wizardReview{Name: name, ID: id}, "")
}

func (p pages) connectionWizardSave(w http.ResponseWriter, r *http.Request) {
	cfg, loc := p.wizardForm(w, r, wizardSaveBody)
	if cfg == nil {
		return
	}
	draft, ok := p.takeWizardDraft(w, r, false)
	if !ok {
		p.wizardError(w, r, http.StatusConflict, cfg, loc, "wizard_check_again")
		return
	}
	input := wizardSaveIdentity(cfg, draft.location, r.PostForm)
	if input.NameError != "" || input.IDError != "" {
		p.renderWizardReview(w, r, http.StatusUnprocessableEntity, cfg, draft, input, "")
		return
	}
	candidate := withWizardConnection(cfg, draft.candidates[0].Connection, draft.location.replace, input.ID, input.Name)
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	if err := p.deps.ValidateConnection(ctx, candidate, input.ID); err != nil {
		p.wizardError(w, r, http.StatusUnprocessableEntity, cfg, draft.location, "wizard_validation")
		return
	}
	var unsaved *model.AppliedUnsavedError
	switch err := p.deps.Apply(ctx, candidate, draft.rev); {
	case errors.Is(err, model.ErrConfigChanged):
		p.wizardError(w, r, http.StatusConflict, p.deps.Config(), draft.location, "revision_changed")
	case errors.As(err, &unsaved):
		p.wizardError(w, r, http.StatusInternalServerError, p.deps.Config(), draft.location, "apply_not_saved")
	case err != nil:
		p.renderWizardReview(w, r, http.StatusUnprocessableEntity, cfg, draft, input, "wizard_apply_error")
	default:
		redirectWithFlash(w, r, "/connections", "flash_saved")
	}
}

func (p pages) takeWizardDraft(w http.ResponseWriter, r *http.Request, choosing bool) (connectionDraft, bool) {
	preview := r.PostForm["preview"]
	if len(preview) != 1 || preview[0] == "" {
		return connectionDraft{}, false
	}
	session := p.wizardSession(w, r, false)
	return p.connectionDrafts.take(preview[0], r.PostForm.Get("rev"), session, choosing, time.Now())
}

// wizardForm authorizes first and bounds the complete form before decoding it.
// The multipart length allowance covers only the envelope; readWizardFile
// independently enforces the exact 2 MiB payload limit.
func (p pages) wizardForm(w http.ResponseWriter, r *http.Request, limit int64) (*model.Config, wizardLocation) {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return nil, wizardLocation{}
	}
	if r.ContentLength > limit {
		p.wizardError(w, r, http.StatusRequestEntityTooLarge, p.deps.Config(), wizardLocation{}, "wizard_too_large")
		return nil, wizardLocation{}
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := r.ParseMultipartForm(limit); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) {
			p.wizardError(w, r, http.StatusRequestEntityTooLarge, p.deps.Config(), wizardLocation{}, "wizard_too_large")
		} else {
			p.wizardError(w, r, http.StatusBadRequest, p.deps.Config(), wizardLocation{}, "wizard_invalid")
		}
		return nil, wizardLocation{}
	}
	loc := wizardLocationFor(r.PostForm)
	if replace, ok := r.PostForm["replace"]; ok {
		if len(replace) != 1 {
			p.wizardError(w, r, http.StatusBadRequest, p.deps.Config(), loc, "wizard_invalid")
			return nil, loc
		}
		decoded, err := url.PathUnescape(replace[0])
		loc.replace = connectionIDFromSegment(decoded)
		if err != nil || loc.replace == "" || connectionIDSegment(loc.replace) != replace[0] {
			p.wizardError(w, r, http.StatusBadRequest, p.deps.Config(), loc, "wizard_invalid")
			return nil, loc
		}
	}
	cfg, message := p.checkRevision(r)
	if message != "" {
		p.wizardError(w, r, http.StatusConflict, p.deps.Config(), loc, "revision_changed")
		return nil, loc
	}
	return cfg, loc
}

func connectionIndex(cfg *model.Config, id string) int {
	if cfg == nil {
		return -1
	}
	return slices.IndexFunc(cfg.Connections, func(c model.Connection) bool { return c.ID == id })
}

// withWizardConnection changes one profile without mutating the applied
// snapshot. Replacement retains administrative state and its stable ID.
func withWizardConnection(cfg *model.Config, profile model.Connection, replace, id, name string) *model.Config {
	candidate := *cfg
	candidate.Connections = slices.Clone(cfg.Connections)
	profile.ID, profile.Name = id, name
	if replace == "" {
		candidate.Connections = append(candidate.Connections, profile)
	} else {
		i := connectionIndex(cfg, replace)
		prev := cfg.Connections[i]
		profile.Disabled, profile.Fallback = prev.Disabled, prev.Fallback
		candidate.Connections[i] = profile
	}
	return &candidate
}

var wizardIDFormat = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func wizardSaveIdentity(cfg *model.Config, loc wizardLocation, form url.Values) wizardReview {
	review := wizardReview{Name: strings.TrimSpace(form.Get("name")), ID: loc.replace}
	if len(form["name"]) != 1 || review.Name == "" {
		review.NameError = "wizard_name_required"
	}
	if loc.replace == "" {
		review.ID = form.Get("id")
		switch {
		case len(form["id"]) != 1 || !wizardIDFormat.MatchString(review.ID):
			review.IDError = "wizard_id_format"
		case wizardIDTaken(cfg, review.ID):
			review.IDError = "wizard_id_taken"
		}
	}
	return review
}

func wizardIDTaken(cfg *model.Config, id string) bool {
	return id == model.TargetDirect || id == model.TargetBlock || cfg.HasManagedTarget(id) ||
		connectionIndex(cfg, id) >= 0 || slices.ContainsFunc(cfg.Subscriptions, func(source subscription.Source) bool { return source.ID == id })
}

func availableWizardID(cfg *model.Config, name string) string {
	base := cmp.Or(connectionimport.Slug(name), "connection")
	id := base
	for n := 2; wizardIDTaken(cfg, id); n++ {
		suffix := "-" + strconv.Itoa(n)
		id = base[:min(len(base), 32-len(suffix))] + suffix
	}
	return id
}
