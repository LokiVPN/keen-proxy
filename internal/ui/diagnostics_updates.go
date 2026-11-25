package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/update"
)

type updateConfirmationView struct {
	Path, Token, Title, Warning string
}

func (p pages) updatesCheck(w http.ResponseWriter, r *http.Request) {
	if !p.diagnosticsForm(w, r) {
		return
	}
	if !p.deps.UpdateStatus().Available {
		p.renderDiagnostics(w, r, http.StatusConflict, "diag_updates_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 22*time.Second)
	defer cancel()
	p.deps.CheckUpdates(ctx)
	redirectWithFlash(w, r, diagnosticsPath, "flash_diag_update_checked")
}

// updateAction presents a native confirmation on the first POST and consumes
// its session-bound token before asking the manager to start the release.
func (p pages) updateAction(rollback bool) http.HandlerFunc {
	path, title, warning := "/updates/install", "diag_confirm_install", "diag_restart_hint"
	if rollback {
		path, title, warning = "/updates/rollback", "diag_confirm_rollback", "diag_rollback_warning"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.diagnosticsForm(w, r) {
			return
		}
		if tokens, confirmed := r.PostForm["confirm"]; confirmed {
			p.confirmUpdate(w, r, path, tokens, rollback)
			return
		}
		status := p.deps.UpdateStatus()
		expected := status.Latest
		if rollback {
			expected = status.Previous
		}
		targets := r.PostForm["target"]
		if !status.Available || expected == "" || len(targets) != 1 || targets[0] != expected {
			p.renderDiagnostics(w, r, http.StatusConflict, "diag_release_changed")
			return
		}
		token := p.diagnosticTickets.put(diagnosticTicket{owner: p.diagnosticsOwner(r), purpose: path, target: expected})
		data := p.diagnosticsPageData(w, r)
		data.UpdateConfirmation = updateConfirmationView{
			Path: path, Token: token, Title: fmt.Sprintf(data.Text[title], expected), Warning: data.Text[warning],
		}
		render(w, r, http.StatusOK, "diagnostics-confirm-update", data)
	}
}

func (p pages) confirmUpdate(w http.ResponseWriter, r *http.Request, path string, tokens []string, rollback bool) {
	if len(tokens) != 1 {
		p.renderDiagnostics(w, r, http.StatusBadRequest, "diag_invalid_form")
		return
	}
	ticket, ok := p.diagnosticTickets.get(tokens[0], path, p.diagnosticsOwner(r))
	if !ok {
		p.renderDiagnostics(w, r, http.StatusConflict, "diag_confirmation_expired")
		return
	}
	err := p.deps.StartUpdate(ticket.target, rollback)
	switch {
	case errors.Is(err, update.ErrTarget):
		p.renderDiagnostics(w, r, http.StatusConflict, "diag_release_changed")
	case errors.Is(err, update.ErrBusy):
		p.renderDiagnostics(w, r, http.StatusConflict, "diag_update_busy")
	case errors.Is(err, update.ErrUnavailable):
		p.renderDiagnostics(w, r, http.StatusConflict, "diag_updates_unavailable")
	case err != nil:
		p.renderDiagnostics(w, r, http.StatusServiceUnavailable, "diag_update_error")
	default:
		redirectWithFlash(w, r, diagnosticsPath, "flash_diag_update_started")
	}
}

func (p pages) updatePreferences(w http.ResponseWriter, r *http.Request) {
	if !p.diagnosticsForm(w, r) {
		return
	}
	rev, enabled, clock := r.PostForm["rev"], r.PostForm["enabled"], r.PostForm["time"]
	if len(rev) != 1 || rev[0] == "" {
		p.renderDiagnostics(w, r, http.StatusConflict, "revision_changed")
		return
	}
	if len(clock) != 1 || len(enabled) > 1 || (len(enabled) == 1 && enabled[0] != "1") {
		p.renderDiagnostics(w, r, http.StatusBadRequest, "diag_invalid_form")
		return
	}
	err := p.deps.SaveUpdatePreferences(update.Preferences{Enabled: len(enabled) == 1, Time: clock[0]}, rev[0])
	switch {
	case errors.Is(err, update.ErrPreferencesChanged):
		p.renderDiagnostics(w, r, http.StatusConflict, "revision_changed")
	case errors.Is(err, update.ErrPreferences):
		p.renderDiagnostics(w, r, http.StatusUnprocessableEntity, "diag_invalid_time")
	case errors.Is(err, update.ErrUnavailable):
		p.renderDiagnostics(w, r, http.StatusConflict, "diag_updates_unavailable")
	case err != nil:
		p.renderDiagnostics(w, r, http.StatusServiceUnavailable, "diag_preferences_error")
	default:
		redirectWithFlash(w, r, diagnosticsPath, "flash_saved")
	}
}
