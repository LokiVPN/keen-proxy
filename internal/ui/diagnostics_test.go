package ui

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/connectionimport"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/update"
)

func TestDiagnosticsRendersMissingBlocks(t *testing.T) {
	for _, role := range []Role{RoleManage, RoleView} {
		h := New(&diagnosticsFixture{}, Options{Role: func(*http.Request) Role { return role }})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/diagnostics", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("diagnostics HTTP %d, want 200", w.Code)
		}
		assertPageHeaders(t, w.Result(), "en")
		body := w.Body.String()
		for _, label := range []string{
			"sing-box core", "Traffic interception", "DNS", "Configuration", "Country database",
			"Firewall watchdog", "Router", "Connection check", "HTTPS with certificate verification",
			"64 KiB transfer", "Support report", "Download ZIP", "Updates", "Install automatically",
		} {
			if !strings.Contains(body, label) {
				t.Errorf("diagnostics is missing %q for role %d", label, role)
			}
		}
		if !strings.Contains(body, "\u2014") || strings.Contains(body, "style=") {
			t.Error("diagnostics needs explicit missing values and CSP-compatible markup")
		}
	}
}

type diagnosticUpdate struct {
	target   string
	rollback bool
}

type diagnosticsFixture struct {
	fakeDeps
	state      DiagnosticStatus
	subs       []AppliedSubscription
	pinned     DiagnosticNode
	checkedAt  time.Time
	group      string
	leaf       string
	skippedVPN bool
	probes     []DiagnosticProbe
	probeErr   error
	checked    []string
	updates    update.Status
	starts     []diagnosticUpdate
	refreshes  int
	writes     int
}

func (f *diagnosticsFixture) DiagnosticStatus(context.Context) DiagnosticStatus { return f.state }

func (f *diagnosticsFixture) Subscriptions() []AppliedSubscription { return f.subs }

func (f *diagnosticsFixture) DiagnosticNode(string) DiagnosticNode { return f.pinned }

func (f *diagnosticsFixture) CheckDiagnosticTarget(_ context.Context, target, _ string) (DiagnosticCheckResult, error) {
	f.checked = append(f.checked, target)
	result := DiagnosticCheckResult{
		Node: f.pinned, Probes: f.probes, CheckedAt: f.checkedAt,
		Group: f.group, Leaf: f.leaf, SkippedVPN: f.skippedVPN,
	}
	for _, sub := range f.subs {
		for i, node := range sub.Nodes {
			if node.ID == sub.ActiveNode {
				result.Node = DiagnosticNode{Name: node.Name, Position: i + 1}
				break
			}
		}
	}
	return result, f.probeErr
}

func (f *diagnosticsFixture) UpdateStatus() update.Status { return f.updates }

func (f *diagnosticsFixture) CheckUpdates(context.Context) { f.refreshes++ }

func (f *diagnosticsFixture) StartUpdate(target string, rollback bool) error {
	f.starts = append(f.starts, diagnosticUpdate{target, rollback})
	return nil
}

func (f *diagnosticsFixture) SaveUpdatePreferences(prefs update.Preferences, rev string) error {
	if f.updates.Preferences.Revision() != rev {
		return update.ErrPreferencesChanged
	}
	f.writes++
	f.updates.Preferences = prefs
	return nil
}

func diagnosticRequest(h http.Handler, method, path, session string, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Test-Session", session)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func diagnosticsHandler(f *diagnosticsFixture) http.Handler {
	return New(f, Options{
		Role: func(*http.Request) Role { return RoleManage },
		SessionKey: func(r *http.Request) [sha256.Size]byte {
			return sha256.Sum256([]byte(r.Header.Get("X-Test-Session")))
		},
	})
}

func TestDiagnosticsStateRendersDaemonFactsWithPartialResourceSamples(t *testing.T) {
	at := time.Date(2026, 11, 1, 9, 12, 0, 0, time.Local)
	f := &diagnosticsFixture{state: DiagnosticStatus{
		Started: at.Add(-time.Minute), AppliedAt: at, Core: true, Firewall: true, DNS: true,
		Mode: "tproxy", GeoLoaded: true, GeoBuilt: "2026-11-01", Restorations: 2,
		System: stats.System{CPU: 0, CPUKnown: true, MemMB: 256, MemPct: 100, Process: &stats.ProcessUsage{RSSBytes: 46 << 20}},
		Build:  "KeenProxy v0.11.0 · arm64 · full",
	}}
	w := diagnosticRequest(diagnosticsHandler(f), http.MethodGet, "/diagnostics", "owner", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("diagnostics HTTP %d, want 200", w.Code)
	}
	assertContains(t, w.Body.String(),
		"Working", "TCP and UDP", "09:12", "Loaded, released", "2 repairs since start",
		"CPU 0 % · RAM \u2014", "CPU \u2014 · RAM 46 MiB",
		"KeenProxy v0.11.0 · arm64 · full", `data-copy="diagnostics-build"`,
	)
	f.state.System.MemKnown, f.state.System.MemPct = true, 0
	w = diagnosticRequest(diagnosticsHandler(f), http.MethodGet, "/diagnostics", "owner", nil)
	assertContains(t, w.Body.String(), "CPU 0 % · RAM 0 %")
}

func TestDiagnosticsPinnedLabelHidesCredentialsForBothRoles(t *testing.T) {
	const uuid = "a7e68fba-cd36-4079-9c4a-fa7b5c8d93a2"
	const compact = "a7E68fbaCd3640799C4aFa7b5c8D93a2"
	const name = "Region " + compact
	link := "vless://" + uuid + "@proxy.example.test:443#" + url.PathEscape(name)
	node := strings.Repeat("a", 32)
	cfg := &model.Config{
		Networks:      []model.Network{{Name: "Home", Target: model.ManagedTarget("main", node)}},
		Subscriptions: []subscription.Source{{ID: "main"}},
	}
	f := &diagnosticsFixture{
		fakeDeps: fakeDeps{config: cfg},
		pinned:   DiagnosticNode{Name: connectionimport.SafeLinkLabel(link, name), Position: 2},
		probes:   []DiagnosticProbe{{Kind: "http", OK: true, LatencyMS: 38}},
	}
	for _, role := range []Role{RoleManage, RoleView} {
		h := New(f, Options{Role: func(*http.Request) Role { return role }})
		w := diagnosticRequest(h, http.MethodGet, "/diagnostics", "", nil)
		body := w.Body.String()
		if w.Code != http.StatusOK || strings.Contains(strings.ToLower(body), strings.ToLower(compact)) || !strings.Contains(body, `value="Node 2"`) {
			t.Errorf("role %d did not get a generic pinned label", role)
		}
	}
	h := diagnosticsHandler(f)
	check := diagnosticRequest(h, http.MethodPost, "/diagnostics/check", "owner", url.Values{"rev": {Revision(cfg)}})
	if check.Code != http.StatusSeeOther {
		t.Fatalf("diagnostics returned HTTP %d", check.Code)
	}
	location := check.Header().Get("Location")
	fragment := strings.Replace(location, "/diagnostics?", "/fragments/diagnostics/check?", 1)
	for _, path := range []string{location, fragment} {
		result := diagnosticRequest(h, http.MethodGet, path, "owner", nil)
		body := result.Body.String()
		if result.Code != http.StatusOK || strings.Contains(strings.ToLower(body), strings.ToLower(compact)) ||
			!strings.Contains(body, "Tested Node 2") {
			t.Error("diagnostics result did not mask the tested node name")
		}
	}
}

func TestDiagnosticsKeepsTestedNodeAcrossSelectionChanges(t *testing.T) {
	first, second := strings.Repeat("a", 32), strings.Repeat("b", 32)
	cfg := &model.Config{
		Networks:      []model.Network{{Name: "Home", Target: model.ManagedTarget("main", "auto")}},
		Subscriptions: []subscription.Source{{ID: "main"}},
	}
	f := &diagnosticsFixture{
		fakeDeps: fakeDeps{config: cfg}, probes: []DiagnosticProbe{{Kind: "http", OK: true, LatencyMS: 38}},
		checkedAt: time.Date(2026, 11, 1, 10, 2, 0, 0, time.Local),
		subs: []AppliedSubscription{
			{ID: "main", ActiveNode: first, Nodes: []SubscriptionNode{{ID: first, Name: "First region"}, {ID: second, Name: "Second region"}}},
		},
	}
	h := diagnosticsHandler(f)
	form := url.Values{"rev": {Revision(cfg)}}
	firstCheck := diagnosticRequest(h, http.MethodPost, "/diagnostics/check", "owner", form)
	if firstCheck.Code != http.StatusSeeOther {
		t.Fatalf("first check returned HTTP %d", firstCheck.Code)
	}
	f.subs[0].ActiveNode = second
	f.checkedAt = f.checkedAt.Add(time.Minute)
	secondCheck := diagnosticRequest(h, http.MethodPost, "/diagnostics/check", "owner", form)
	if secondCheck.Code != http.StatusSeeOther {
		t.Fatalf("second check returned HTTP %d", secondCheck.Code)
	}
	for _, check := range []struct {
		response          *httptest.ResponseRecorder
		want, other, time string
	}{
		{firstCheck, "First region", "Second region", "10:02"},
		{secondCheck, "Second region", "First region", "10:03"},
	} {
		location := check.response.Header().Get("Location")
		fragment := strings.Replace(location, "/diagnostics?", "/fragments/diagnostics/check?", 1)
		for _, path := range []string{location, fragment} {
			w := diagnosticRequest(h, http.MethodGet, path, "owner", nil)
			body := w.Body.String()
			if w.Code != http.StatusOK || !strings.Contains(body, check.want) || strings.Contains(body, check.other) ||
				!strings.Contains(body, check.time) {
				t.Errorf("the result for %s lost the actual tested identity", check.want)
			}
		}
	}
}

func TestDiagnosticsReportsTheSelectedGroupPath(t *testing.T) {
	cfg := &model.Config{
		Networks: []model.Network{{Name: "Home", Target: "office"}},
		Connections: []model.Connection{
			{ID: "office", Name: "Office <group>"},
			{ID: "vpn", Name: "VPN tunnel"},
			{ID: "reserve", Name: "Direct reserve"},
		},
	}
	const skippedMessage = "The main VPN path is not in use. No VPN check was run."
	for _, tc := range []struct {
		leaf, label string
		skipped     bool
	}{
		{leaf: "vpn", label: "VPN tunnel"},
		{leaf: "reserve", label: "Direct reserve", skipped: true},
	} {
		t.Run(tc.leaf, func(t *testing.T) {
			f := &diagnosticsFixture{
				fakeDeps: fakeDeps{config: cfg}, group: "office", leaf: tc.leaf, skippedVPN: tc.skipped,
				probes: []DiagnosticProbe{{Kind: "http", OK: true, LatencyMS: 38}},
			}
			h := diagnosticsHandler(f)
			post := diagnosticRequest(h, http.MethodPost, "/diagnostics/check", "owner", url.Values{"rev": {Revision(cfg)}})
			if post.Code != http.StatusSeeOther {
				t.Fatalf("group diagnostics returned HTTP %d", post.Code)
			}
			for _, cookie := range post.Result().Cookies() {
				if tc.skipped && cookie.Value == "flash_diag_checked" {
					t.Error("skipped VPN check produced a completion flash")
				}
			}
			location := post.Header().Get("Location")
			fragment := strings.Replace(location, "/diagnostics?", "/fragments/diagnostics/check?", 1)
			for _, path := range []string{location, fragment} {
				w := diagnosticRequest(h, http.MethodGet, path, "owner", nil)
				body := w.Body.String()
				if w.Code != http.StatusOK || !strings.Contains(body, "Office &lt;group&gt; → "+tc.label) ||
					strings.Contains(body, skippedMessage) != tc.skipped || strings.Contains(body, "38 ms") == tc.skipped {
					t.Errorf("%s did not report the selected route and its probe state", tc.leaf)
				}
			}
		})
	}
}

func TestDiagnosticsChecksOnlyCurrentMainTarget(t *testing.T) {
	cfg := &model.Config{
		Networks: []model.Network{{Name: "Home", Target: "primary"}},
		Connections: []model.Connection{
			{ID: "primary", Name: "<script>primary</script>", Fallback: "reserve"},
			{ID: "reserve"},
		},
	}
	f := &diagnosticsFixture{fakeDeps: fakeDeps{config: cfg}, probes: []DiagnosticProbe{
		{Kind: "http", OK: true, LatencyMS: 38},
		{Kind: "https"},
		{Kind: "transfer", OK: true, LatencyMS: 180},
	}}
	h := diagnosticsHandler(f)
	stale := diagnosticRequest(h, http.MethodPost, "/diagnostics/check", "owner", url.Values{"rev": {"stale"}})
	if stale.Code != http.StatusConflict || len(f.checked) != 0 {
		t.Fatalf("stale check HTTP %d, calls %v", stale.Code, f.checked)
	}
	form := url.Values{"rev": {Revision(cfg)}, "target": {"reserve"}}
	check := diagnosticRequest(h, http.MethodPost, "/diagnostics/check", "owner", form)
	if check.Code != http.StatusSeeOther || len(f.checked) != 1 || f.checked[0] != "primary" {
		t.Fatalf("main check HTTP %d, targets %v", check.Code, f.checked)
	}
	location := check.Header().Get("Location")
	page := diagnosticRequest(h, http.MethodGet, location, "owner", nil)
	assertContains(t, page.Body.String(), "38 ms", "180 ms", "Failed", "&lt;script&gt;primary&lt;/script&gt;")
	if strings.Contains(page.Body.String(), "<script>primary") {
		t.Fatal("target label was not escaped")
	}
	u, err := url.Parse(location)
	if err != nil || u.Query().Get("result") == "" {
		t.Fatalf("check did not redirect to a result: %q", location)
	}
	frag := "/fragments/diagnostics/check?" + u.RawQuery
	result := diagnosticRequest(h, http.MethodGet, frag, "owner", nil)
	assertPageHeaders(t, result.Result(), "en")
	assertContains(t, result.Body.String(), "38 ms", "180 ms", "Failed")
	if result.Code != http.StatusOK || strings.Contains(result.Body.String(), "<main") {
		t.Fatal("check result is not an HTML fragment")
	}
	other := diagnosticRequest(h, http.MethodGet, frag, "different-session", nil)
	if strings.Contains(other.Body.String(), "38 ms") {
		t.Fatal("a different session saw the probe result")
	}
	f.probeErr = errors.New("synthetic private error https://admin.example.test/credential")
	failed := diagnosticRequest(h, http.MethodPost, "/diagnostics/check", "owner", form)
	if failed.Code != http.StatusServiceUnavailable || strings.Contains(failed.Body.String(), "admin.example.test") {
		t.Fatal("connection check error was not handled with a fixed message")
	}
	assertContains(t, failed.Body.String(), "The main connection could not be checked.")
	f.probeErr = ErrDiagnosticPath
	refused := diagnosticRequest(h, http.MethodPost, "/diagnostics/check", "owner", form)
	if refused.Code != http.StatusUnprocessableEntity {
		t.Fatalf("dependent path refusal HTTP %d, want 422", refused.Code)
	}
	assertContains(t, refused.Body.String(), "This check requires a connection that can be dialed without a detour or reserve.")
}

func TestDiagnosticsRequiresConfirmationBeforeStartingUpdates(t *testing.T) {
	f := &diagnosticsFixture{updates: update.Status{
		Available: true, Current: "v0.11.0", Latest: "v0.11.1", Previous: "v0.10.1",
		Preferences: update.Preferences{Time: "04:00"},
	}}
	h := diagnosticsHandler(f)
	for _, tc := range []struct {
		path, target, otherPath, title string
		rollback                       bool
	}{
		{"/updates/install", f.updates.Latest, "/updates/rollback", "Install v0.11.1?", false},
		{"/updates/rollback", f.updates.Previous, "/updates/install", "Roll back to v0.10.1?", true},
	} {
		t.Run(tc.path, func(t *testing.T) {
			before := len(f.starts)
			diagnosticRequest(h, http.MethodGet, tc.path, "owner", nil)
			forged := diagnosticRequest(h, http.MethodPost, tc.path, "owner", url.Values{"confirm": {"forged"}})
			if len(f.starts) != before || forged.Code != http.StatusConflict {
				t.Fatal("GET or a direct confirmation could start an update")
			}
			confirm := diagnosticRequest(h, http.MethodPost, tc.path, "owner", url.Values{"target": {tc.target}})
			if confirm.Code != http.StatusOK || len(f.starts) != before {
				t.Fatalf("confirmation HTTP %d, starts %v", confirm.Code, f.starts)
			}
			assertContains(t, confirm.Body.String(), tc.title, "Confirm", "Cancel")
			token := regexp.MustCompile(`name="confirm" value="([^"]+)"`).FindStringSubmatch(confirm.Body.String())
			if len(token) != 2 {
				t.Fatal("confirmation form did not carry a token")
			}
			form := url.Values{"confirm": {token[1]}}
			wrongSession := diagnosticRequest(h, http.MethodPost, tc.path, "different-session", form)
			wrongAction := diagnosticRequest(h, http.MethodPost, tc.otherPath, "owner", form)
			if wrongSession.Code != http.StatusConflict || wrongAction.Code != http.StatusConflict || len(f.starts) != before {
				t.Fatal("confirmation worked for a different session or action")
			}
			done := diagnosticRequest(h, http.MethodPost, tc.path, "owner", form)
			if done.Code != http.StatusSeeOther || len(f.starts) != before+1 || f.starts[before] != (diagnosticUpdate{tc.target, tc.rollback}) {
				t.Fatalf("confirmed update HTTP %d, starts %v", done.Code, f.starts)
			}
			replayed := diagnosticRequest(h, http.MethodPost, tc.path, "owner", form)
			if replayed.Code != http.StatusConflict || len(f.starts) != before+1 {
				t.Fatal("the same confirmation could start an update twice")
			}
		})
	}
	if w := diagnosticRequest(h, http.MethodPost, "/updates/check", "owner", nil); w.Code != http.StatusSeeOther || f.refreshes != 1 {
		t.Fatalf("release check HTTP %d, calls %d", w.Code, f.refreshes)
	}
}

func TestDiagnosticsScheduleUsesItsOwnRevision(t *testing.T) {
	f := &diagnosticsFixture{updates: update.Status{
		Available: true, Current: "v0.11.0", Preferences: update.Preferences{Time: "04:00"},
	}}
	h := diagnosticsHandler(f)
	page := diagnosticRequest(h, http.MethodGet, "/diagnostics", "owner", nil)
	revision := f.updates.Preferences.Revision()
	assertContains(t, page.Body.String(), `name="rev" value="`+revision+`"`, `name="time" value="04:00"`)
	form := url.Values{"rev": {revision}, "enabled": {"1"}, "time": {"05:30"}}
	saved := diagnosticRequest(h, http.MethodPost, "/updates/preferences", "owner", form)
	if saved.Code != http.StatusSeeOther || f.writes != 1 || f.updates.Preferences != (update.Preferences{Enabled: true, Time: "05:30"}) {
		t.Fatalf("save schedule HTTP %d, preferences %+v", saved.Code, f.updates.Preferences)
	}
	form.Set("time", "06:45")
	stale := diagnosticRequest(h, http.MethodPost, "/updates/preferences", "owner", form)
	if stale.Code != http.StatusConflict || f.writes != 1 {
		t.Fatalf("stale schedule HTTP %d, writes %d", stale.Code, f.writes)
	}
	assertContains(t, stale.Body.String(), "Settings changed in another window", `name="time" value="05:30"`)
}

func TestDiagnosticsForbidsViewActions(t *testing.T) {
	// fakeDeps panics on any unimplemented operation. Refusals must reach
	// neither the updater nor the other diagnostics dependencies.
	h := New(fakeDeps{}, Options{Role: func(*http.Request) Role { return RoleView }})
	for _, path := range []string{
		"/diagnostics/check", "/updates/check", "/updates/install", "/updates/rollback", "/updates/preferences",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
			if w.Code != http.StatusForbidden {
				t.Errorf("POST %s returned HTTP %d, want 403", path, w.Code)
			}
		})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/diagnostics/bundle.zip", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("view ZIP returned HTTP %d, want 403", w.Code)
	}
}
