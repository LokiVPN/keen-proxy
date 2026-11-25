package main

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/api"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/ui"
	"github.com/ordo-systems/keen-proxy/internal/update"
)

func (d uiDeps) DiagnosticStatus(ctx context.Context) ui.DiagnosticStatus {
	st := d.daemon.Status(ctx)
	build := api.RunningBuild()
	version := "KeenProxy"
	if build.Version != "" {
		version += " " + build.Version
	}
	revision := build.Revision
	if build.Dirty && revision != "" {
		revision += "*"
	}
	info := []string{version, build.Arch, build.Variant, revision}
	return ui.DiagnosticStatus{
		Started: st.Started, AppliedAt: st.AppliedAt,
		Core: st.CoreRunning, Firewall: st.Firewall, DNS: st.DNS != "", Paused: st.Paused,
		Mode: st.Mode, GeoBuilt: st.GeoIP.Built, GeoLoaded: st.GeoIP.Loaded,
		Restorations: st.Restored, System: d.daemon.SystemStats(),
		Build: strings.Join(slices.DeleteFunc(info, func(part string) bool { return part == "" }), " · "),
	}
}

func (d uiDeps) DiagnosticNode(target string) ui.DiagnosticNode {
	return ui.DiagnosticNode(d.daemon.DiagnosticNode(target))
}

func (d uiDeps) CheckDiagnosticTarget(ctx context.Context, target, revision string) (ui.DiagnosticCheckResult, error) {
	report, err := d.daemon.DiagnosticTargetIfCurrent(ctx, target, revision)
	if errors.Is(err, engine.ErrDiagnosticPath) {
		return ui.DiagnosticCheckResult{}, ui.ErrDiagnosticPath
	}
	if err != nil {
		return ui.DiagnosticCheckResult{}, err
	}
	probes := make([]ui.DiagnosticProbe, 0, len(report.Results))
	for _, result := range report.Results {
		probes = append(probes, ui.DiagnosticProbe{Kind: result.Kind, OK: result.OK, LatencyMS: result.Latency})
	}
	return ui.DiagnosticCheckResult{
		Probes: probes, Node: ui.DiagnosticNode(report.Node), CheckedAt: report.CheckedAt,
		Group: report.Group, Leaf: report.Connection, SkippedVPN: report.SkippedVPN,
	}, nil
}

func (d uiDeps) SupportBundle(w http.ResponseWriter, r *http.Request) {
	if d.bundle == nil {
		http.Error(w, "diagnostic archive unavailable", http.StatusServiceUnavailable)
		return
	}
	d.bundle(w, r)
}

func (d uiDeps) UpdateStatus() update.Status { return d.updates.Status() }

func (d uiDeps) CheckUpdates(ctx context.Context) { d.updates.Check(ctx, true) }

func (d uiDeps) StartUpdate(target string, rollback bool) error {
	return d.updates.Start(target, rollback)
}

func (d uiDeps) SaveUpdatePreferences(prefs update.Preferences, revision string) error {
	return d.updates.SetPreferencesIfCurrent(prefs, revision)
}
