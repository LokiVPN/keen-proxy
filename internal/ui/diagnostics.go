package ui

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

const (
	diagnosticsPath     = "/diagnostics"
	diagnosticsFragment = "/fragments/diagnostics/check"
	diagnosticsFormSize = 4 << 10
)

// ErrDiagnosticPath maps a reserved or dependent dial to fixed page copy.
var ErrDiagnosticPath = errors.New("diagnostic path requires a detour or reserve")

// ErrDiagnosticNotRouting maps inactive routing to the localized check refusal.
var ErrDiagnosticNotRouting = errors.New("routing is inactive")

func (p pages) diagnosticsGet(w http.ResponseWriter, r *http.Request) {
	if !p.canReadDiagnostics(w, r) {
		return
	}
	p.renderDiagnostics(w, r, http.StatusOK, "")
}

func (p pages) renderDiagnostics(w http.ResponseWriter, r *http.Request, status int, message string) {
	data := p.diagnosticsPageData(w, r)
	cfg := p.deps.Config()
	rev := Revision(cfg)
	st := p.deps.DiagnosticStatus(r.Context())
	label, canCheck := p.diagnosticTargetLabel(cfg, data.Text)
	result, query := p.lastDiagnosticCheck(r, rev)
	data.Message = data.Text[message]
	data.Diagnostics = diagnosticsPage{
		Revision: rev, Target: label, CanCheck: canCheck, CanDownload: cfg != nil,
		State:   diagnosticStateRows(st, data.Lang, data.Text),
		Updated: time.Now().Format("15:04"),
		Build:   st.Build, Updates: diagnosticsUpdates(p.deps.UpdateStatus(), data.Text),
		RefreshURL: diagnosticsPath + query,
	}
	if query != "" {
		data.Diagnostics.FragmentURL = diagnosticsFragment + query
	}
	data.DiagnosticResult = diagnosticResult(result, cfg, data.Text)
	render(w, r, status, "diagnostics", data)
}

func (p pages) diagnosticsPageData(w http.ResponseWriter, r *http.Request) pageData {
	data := p.opts.pageData(r)
	data.Title = data.Text["nav_diagnostics"]
	data.ActiveTab, data.SignedIn = diagnosticsPath, true
	data.ViewOnly = p.role(r) == RoleView
	data.Flash = takeFlash(w, r, data.Text)
	return data
}

func (p pages) diagnosticsCheck(w http.ResponseWriter, r *http.Request) {
	if !p.diagnosticsForm(w, r) {
		return
	}
	cfg, conflict := p.checkRevision(r)
	if conflict != "" {
		p.renderDiagnostics(w, r, http.StatusConflict, "revision_changed")
		return
	}
	network := cfg.HomeNetwork()
	if network == nil || network.Target == "" {
		p.renderDiagnostics(w, r, http.StatusUnprocessableEntity, "diag_check_unavailable")
		return
	}
	rev := r.PostForm.Get("rev")
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	result, err := p.deps.CheckDiagnosticTarget(ctx, network.Target, rev)
	switch {
	case errors.Is(err, model.ErrConfigChanged):
		p.renderDiagnostics(w, r, http.StatusConflict, "revision_changed")
	case errors.Is(err, ErrDiagnosticNotRouting):
		p.renderDiagnostics(w, r, http.StatusServiceUnavailable, "diag_check_not_routing")
	case errors.Is(err, ErrDiagnosticPath):
		p.renderDiagnostics(w, r, http.StatusUnprocessableEntity, "diag_check_detour")
	case err != nil:
		p.renderDiagnostics(w, r, http.StatusServiceUnavailable, "diag_check_unavailable")
	default:
		token := p.diagnosticTickets.put(diagnosticTicket{
			owner: p.diagnosticsOwner(r), purpose: diagnosticsFragment,
			revision: rev, check: result,
		})
		flash := "flash_diag_checked"
		if result.SkippedVPN {
			flash = ""
			setFlashCookie(w, r, "", -1)
		}
		redirectWithFlash(w, r, diagnosticsPath+"?result="+token, flash)
	}
}

func (p pages) diagnosticsCheckFragment(w http.ResponseWriter, r *http.Request) {
	if !p.canReadDiagnostics(w, r) {
		return
	}
	data := p.opts.pageData(r)
	cfg := p.deps.Config()
	result, _ := p.lastDiagnosticCheck(r, Revision(cfg))
	data.DiagnosticResult = diagnosticResult(result, cfg, data.Text)
	render(w, r, http.StatusOK, "diagnostics-probes", data)
}

func (p pages) lastDiagnosticCheck(r *http.Request, revision string) (DiagnosticCheckResult, string) {
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && p.role(r) == RoleManage {
		token := r.URL.Query().Get("result")
		if ticket, ok := p.diagnosticTickets.get(token, diagnosticsFragment, p.diagnosticsOwner(r)); ok && ticket.revision == revision {
			return ticket.check, "?result=" + ticket.token
		}
	}
	return DiagnosticCheckResult{}, ""
}

func (p pages) diagnosticsBundle(w http.ResponseWriter, r *http.Request) {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	p.deps.SupportBundle(w, r)
}

func (p pages) canReadDiagnostics(w http.ResponseWriter, r *http.Request) bool {
	if role := p.role(r); role == RoleView || role == RoleManage {
		return true
	}
	p.opts.AccessError(w, r, http.StatusForbidden)
	return false
}

// diagnosticsForm admits a bounded native POST after the central origin check.
func (p pages) diagnosticsForm(w http.ResponseWriter, r *http.Request) bool {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, diagnosticsFormSize)
	if err := r.ParseForm(); err != nil {
		p.renderDiagnostics(w, r, http.StatusBadRequest, "diag_invalid_form")
		return false
	}
	return true
}
