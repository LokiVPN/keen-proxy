package ui

import (
	"cmp"
	"fmt"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/update"
)

const diagnosticUnknown = "\u2014"

type diagnosticsPage struct {
	Revision, Target, Updated, Build string
	CanCheck, CanDownload            bool
	State                            []diagnosticRow
	RefreshURL, FragmentURL          string
	Updates                          diagnosticsUpdateView
}

type diagnosticRow struct {
	Label, Value string
	Chip         overviewChip
}

func diagnosticStateRows(status DiagnosticStatus, lang string, text map[string]string) []diagnosticRow {
	known := !status.Started.IsZero()
	core := diagnosticService(text["diag_core"], known, status.Core, text)
	interception := diagnosticService(text["diag_interception"], known, status.Firewall, text)
	if status.Paused {
		interception.Chip = overviewChip{Label: text["overview_disabled"]}
	}
	switch status.Mode {
	case string(model.InterceptRedirect):
		interception.Value = text["diag_tcp"]
	case string(model.InterceptTProxy):
		interception.Value = text["diag_tcp_udp"]
	}
	applied, geo, repairs := diagnosticUnknown, diagnosticUnknown, diagnosticUnknown
	if !status.AppliedAt.IsZero() {
		applied = fmt.Sprintf(text["diag_applied"], overviewTimestamp(status.AppliedAt, text))
	}
	if known {
		geo = text["diag_geo_missing"]
		repairs = fmt.Sprintf(text["diag_repairs"], status.Restorations)
	}
	if status.GeoLoaded {
		geo = text["diag_geo_loaded"]
		if date, err := time.Parse(time.DateOnly, status.GeoBuilt); err == nil && !date.IsZero() {
			geo = fmt.Sprintf(text["diag_geo_release"], setupDate(date, text))
		}
	}
	system := status.System
	routerCPU := diagnosticPercent(system.CPU, system.CPUKnown, lang, text)
	routerRAM := diagnosticPercent(system.MemPct, system.MemKnown, lang, text)
	processCPU, processRAM := diagnosticUnknown, diagnosticUnknown
	if process := system.Process; process != nil {
		if process.CPU != nil {
			processCPU = diagnosticPercent(*process.CPU, true, lang, text)
		}
		processRAM = fmt.Sprintf(text["diag_mib"], diagnosticNumber(float64(process.RSSBytes)/(1<<20), lang))
	}
	return []diagnosticRow{
		core, interception, diagnosticService("DNS", known, status.DNS, text),
		{Label: text["diag_config"], Value: applied},
		{Label: text["diag_geo"], Value: geo},
		{Label: text["diag_watchdog"], Value: repairs},
		{Label: text["diag_router"], Value: fmt.Sprintf(text["diag_resources"], routerCPU, routerRAM)},
		{Label: "KeenProxy", Value: fmt.Sprintf(text["diag_resources"], processCPU, processRAM)},
	}
}

func diagnosticService(label string, known, running bool, text map[string]string) diagnosticRow {
	row := diagnosticRow{Label: label}
	switch {
	case !known:
		row.Value = diagnosticUnknown
	case running:
		row.Chip = overviewChip{Label: text["overview_working"], Class: "ok"}
	default:
		row.Chip = overviewChip{Label: text["diag_stopped"], Class: "warn"}
	}
	return row
}

func diagnosticPercent(value float64, known bool, lang string, text map[string]string) string {
	if !known {
		return diagnosticUnknown
	}
	return fmt.Sprintf(text["diag_percent"], diagnosticNumber(value, lang))
}

func diagnosticNumber(value float64, lang string) string {
	number := strings.TrimSuffix(fmt.Sprintf("%.1f", value), ".0")
	if lang == "ru" {
		number = strings.Replace(number, ".", ",", 1)
	}
	return number
}

// diagnosticTargetLabel displays the configured target even when traffic has
// switched to its reserve. The daemon resolves the path for each check.
func (p pages) diagnosticTargetLabel(cfg *model.Config, text map[string]string) (string, bool) {
	if cfg == nil {
		return diagnosticUnknown, false
	}
	network := homeNetwork(cfg)
	if network == nil || network.Target == "" {
		return diagnosticUnknown, false
	}
	target := network.Target
	switch {
	case target == model.TargetDirect:
		return text["overview_direct"], true
	case cfg.HasManagedTarget(target):
		id, mode, _ := model.ParseManagedTarget(target)
		var label string
		switch mode {
		case "auto":
			label = text["diag_automatic_node"]
		case model.SubscriptionRoundRobin:
			label = text["overview_round_robin"]
		case model.SubscriptionConsistentHash:
			label = text["overview_consistent_hash"]
		case model.SubscriptionStickySession:
			label = text["overview_sticky_session"]
		default:
			return cmp.Or(diagnosticNodeName(p.deps.DiagnosticNode(target), text), text["diag_subscription_node"]), true
		}
		sub := appliedSubscriptionFor(p.deps.Subscriptions(), id)
		return sub.title(text) + " · " + label, true
	default:
		for _, conn := range cfg.Connections {
			if conn.ID == target {
				return cmp.Or(conn.Name, conn.ID), !conn.Disabled
			}
		}
	}
	return diagnosticUnknown, false
}

func diagnosticNodeName(node DiagnosticNode, text map[string]string) string {
	if node.Name != "" {
		return node.Name
	}
	if node.Position > 0 {
		return fmt.Sprintf(text["diag_generic_node"], node.Position)
	}
	return ""
}

type diagnosticResultView struct {
	Path, Node, Checked string
	SkippedVPN          bool
	Rows                []diagnosticRow
}

func diagnosticResult(result DiagnosticCheckResult, cfg *model.Config, text map[string]string) diagnosticResultView {
	view := diagnosticResultView{Node: diagnosticNodeName(result.Node, text), SkippedVPN: result.SkippedVPN}
	if result.Group != "" {
		group := cmp.Or(result.GroupName, diagnosticPathName(cfg, result.Group, text))
		leaf := cmp.Or(view.Node, diagnosticPathName(cfg, result.Leaf, text))
		if result.Reserve != "" {
			leaf = fmt.Sprintf(text["diag_reserve"], diagnosticPathName(cfg, result.Reserve, text))
		}
		view.Path = group + " → " + leaf
	}
	if result.SkippedVPN {
		view.Rows = diagnosticProbeRows(nil, text)
		return view
	}
	view.Rows = diagnosticProbeRows(result.Probes, text)
	if !result.CheckedAt.IsZero() {
		view.Checked = overviewTimestamp(result.CheckedAt, text)
	}
	return view
}

func diagnosticPathName(cfg *model.Config, tag string, text map[string]string) string {
	switch tag {
	case model.TargetDirect:
		return text["overview_direct"]
	case model.TargetBlock:
		return text["detail_blocked"]
	}
	if _, _, managed := model.ParseManagedTarget(tag); managed {
		return text["diag_subscription_node"]
	}
	if cfg != nil {
		return cmp.Or(connectionName(cfg, tag), tag)
	}
	return tag
}

func diagnosticProbeRows(probes []DiagnosticProbe, text map[string]string) []diagnosticRow {
	results := []struct{ kind, label string }{
		{"http", "HTTP"}, {"https", text["diag_https"]}, {"transfer", text["diag_transfer"]},
	}
	rows := make([]diagnosticRow, 0, len(results))
	for _, result := range results {
		row := diagnosticRow{Label: result.label, Value: diagnosticUnknown}
		for _, probe := range probes {
			if probe.Kind != result.kind {
				continue
			}
			if probe.OK {
				row.Value = fmt.Sprintf(text["overview_latency"], probe.LatencyMS)
			} else {
				row.Value = ""
				row.Chip = overviewChip{Label: text["diag_probe_failed"], Class: "warn"}
			}
			break
		}
		rows = append(rows, row)
	}
	return rows
}

type diagnosticsUpdateView struct {
	Managed, Enabled, Busy                        bool
	Installed, Latest, Available, Previous        string
	Install, Rollback, Time, Revision, Check, Job string
}

func diagnosticsUpdates(status update.Status, text map[string]string) diagnosticsUpdateView {
	view := diagnosticsUpdateView{
		Managed: status.Available, Installed: fmt.Sprintf(text["diag_installed"], cmp.Or(status.Current, diagnosticUnknown)),
		Latest: status.Latest, Previous: status.Previous, Available: fmt.Sprintf(text["diag_available"], cmp.Or(status.Latest, diagnosticUnknown)),
	}
	if status.Available {
		view.Enabled, view.Time = status.Preferences.Enabled, status.Preferences.Time
		view.Revision = status.Preferences.Revision()
	}
	if status.Latest != "" {
		view.Install = fmt.Sprintf(text["diag_install"], status.Latest)
	}
	if status.Previous != "" {
		view.Rollback = fmt.Sprintf(text["diag_rollback"], status.Previous)
	}
	if status.CheckFailed {
		view.Check = text["diag_release_check_failed"]
	} else if status.CheckedAt != nil && view.Latest == "" {
		view.Check = text["diag_up_to_date"]
	}
	if job := status.Job; job != nil {
		switch job.State {
		case "running":
			view.Busy, view.Job = true, fmt.Sprintf(text["diag_update_running"], job.Target)
		case "success":
			view.Job = fmt.Sprintf(text["diag_update_success"], job.Target)
		case "failed":
			view.Job = fmt.Sprintf(text["diag_update_failed"], job.Target)
		}
	}
	return view
}
