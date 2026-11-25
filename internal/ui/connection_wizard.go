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
		var field connectionimport.ManualField
		var view connectionWizardPage
		if loc.method == "manual" && errors.As(err, &field) {
			view.manualError = string(field)
		} else {
			view.Error = wizardImportError(localized(r), err)
		}
		p.renderConnectionWizard(w, r, status, cfg, loc, view)
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
	if draft.location.method == "manual" {
		name = cmp.Or(name, profile.Summary.Protocol)
	}
	id := draft.location.replace
	if id != "" {
		i := connectionIndex(cfg, id)
		if i < 0 {
			p.notFound(w, r)
			return
		}
		// A replacement must keep its existing ID. If the new profile
		// treats that ID as a credential, refuse without rendering it.
		if profile.ContainsCredential(id) {
			p.renderPage(w, r, http.StatusUnprocessableEntity, localized(r)["wizard_replace"], "wizard_replace_credential")
			return
		}
		name = cmp.Or(cfg.Connections[i].Name, id)
	}
	reserved, err := p.wizardReservedIDs(cfg, id)
	if err != nil {
		p.wizardError(w, r, http.StatusUnprocessableEntity, cfg, draft.location, wizardValidationKey(err))
		return
	}
	review := safeWizardIdentity(profile, name, id, reserved)
	checkID := review.ID
	if checkID == "" {
		// Check the profile even when no safe suggestion can be displayed.
		// Save validates again with the identifier entered on this form.
		checkID = availableWizardID(reserved, "connection")
	}
	candidate := withWizardConnection(cfg, profile.Connection, draft.location.replace, checkID, review.Name)
	if err := p.deps.ValidateConnection(r.Context(), candidate, checkID); err != nil {
		p.wizardError(w, r, http.StatusUnprocessableEntity, cfg, draft.location, wizardValidationKey(err))
		return
	}
	draft.session = p.wizardSession(w, r, true)
	var errorKey string
	if review.Name == "" {
		errorKey = "wizard_identity_unavailable"
	}
	p.renderWizardReview(w, r, http.StatusOK, cfg, draft, review, errorKey)
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
	profile := draft.candidates[0]
	input := wizardSaveIdentity(cfg, draft.location, r.PostForm)
	if profile.ContainsCredential(input.Name, input.ID) {
		reserved, err := p.wizardReservedIDs(cfg, draft.location.replace)
		if err != nil {
			p.wizardError(w, r, http.StatusUnprocessableEntity, cfg, draft.location, wizardValidationKey(err))
			return
		}
		corrected := safeWizardIdentity(profile, "", draft.location.replace, reserved)
		p.renderWizardReview(w, r, http.StatusUnprocessableEntity, cfg, draft, corrected, "wizard_review_identity")
		return
	}
	if input.NameError != "" || input.IDError != "" {
		p.renderWizardReview(w, r, http.StatusUnprocessableEntity, cfg, draft, input, "")
		return
	}
	candidate := withWizardConnection(cfg, profile.Connection, draft.location.replace, input.ID, input.Name)
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	if err := p.deps.ValidateConnection(ctx, candidate, input.ID); err != nil {
		key := wizardValidationKey(err)
		if key == "wizard_tag_conflict" && draft.location.replace == "" {
			input.IDError = key
			p.renderWizardReview(w, r, http.StatusUnprocessableEntity, cfg, draft, input, "")
		} else {
			p.wizardError(w, r, http.StatusUnprocessableEntity, cfg, draft.location, key)
		}
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

func wizardValidationKey(err error) string {
	switch {
	case errors.Is(err, model.ErrConnectionTagConflict):
		return "wizard_tag_conflict"
	case errors.Is(err, connectionimport.ErrRoutingOverride):
		return "wizard_routing_options"
	default:
		return "wizard_validation"
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
	loc := wizardLocationFor(r.URL.Query())
	segment := r.PathValue("id")
	if segment != "" {
		loc.replace = connectionIDFromSegment(segment)
		if loc.replace == "" {
			p.notFound(w, r)
			return nil, loc
		}
	}
	if r.ContentLength > limit {
		p.wizardError(w, r, http.StatusRequestEntityTooLarge, p.deps.Config(), loc, "wizard_too_large")
		return nil, loc
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := r.ParseMultipartForm(limit); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		var maxBytes *http.MaxBytesError
		if errors.As(err, &maxBytes) {
			p.wizardError(w, r, http.StatusRequestEntityTooLarge, p.deps.Config(), loc, "wizard_too_large")
		} else {
			p.wizardError(w, r, http.StatusBadRequest, p.deps.Config(), loc, "wizard_invalid")
		}
		return nil, loc
	}
	selection := wizardLocationFor(r.PostForm)
	loc.method, loc.protocol = selection.method, selection.protocol
	if replace, ok := r.PostForm["replace"]; ok && segment == "" {
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
	review := wizardReview{Name: strings.Join(strings.Fields(form.Get("name")), " "), ID: loc.replace}
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

func (p pages) wizardReservedIDs(cfg *model.Config, fixedID string) (map[string]bool, error) {
	if fixedID != "" {
		return nil, nil
	}
	tags, err := p.deps.ConnectionRuntimeTags(cfg)
	if err != nil {
		return nil, err
	}
	reserved := map[string]bool{model.TargetDirect: true, model.TargetBlock: true}
	for _, tag := range tags {
		reserved[tag] = true
	}
	for _, connection := range cfg.Connections {
		reserved[connection.ID] = true
	}
	for _, source := range cfg.Subscriptions {
		reserved[source.ID] = true
	}
	return reserved, nil
}

// safeWizardIdentity checks the rendered name and the exact final ID against
// the profile after each transformation, including uniqueness suffixing.
func safeWizardIdentity(profile connectionimport.Draft, preferred, fixedID string, reserved map[string]bool) wizardReview {
	suggest := func(name string) wizardReview {
		id := fixedID
		if id == "" {
			id = availableWizardID(reserved, name)
		}
		return wizardReview{Name: name, ID: id}
	}
	if name := strings.Join(strings.Fields(preferred), " "); name != "" {
		if candidate := suggest(name); !profile.ContainsCredential(candidate.Name, candidate.ID) {
			return candidate
		}
	}
	prefix := profile.Summary.Protocol
	if profile.ContainsCredential(prefix, connectionimport.Slug(prefix)) {
		prefix = "Connection"
		if profile.ContainsCredential(prefix, connectionimport.Slug(prefix)) {
			prefix = ""
		}
	}
	// Try the separator-free spelling if every spaced name or hyphenated
	// identifier matches. Leave the identity editable even if both run out.
	for _, separator := range []string{" ", ""} {
		for n := 1; n <= 128; n++ {
			candidate := suggest(strings.TrimSpace(prefix + separator + strconv.Itoa(n)))
			if !profile.ContainsCredential(candidate.Name, candidate.ID) {
				return candidate
			}
		}
	}
	return wizardReview{ID: fixedID}
}

func availableWizardID(reserved map[string]bool, name string) string {
	base := cmp.Or(connectionimport.Slug(name), "connection")
	id := base
	for n := 2; reserved[id]; n++ {
		suffix := "-" + strconv.Itoa(n)
		id = base[:min(len(base), 32-len(suffix))] + suffix
	}
	return id
}
