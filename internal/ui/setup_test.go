package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const setupTestURL = "https://provider.example/list?key=synthetic-token"

func TestSetupEntry(t *testing.T) {
	cfg := &model.Config{}
	h := New(fakeDeps{config: cfg}, setupTestOptions(RoleManage))
	redirect := setupRequest(h, "/", nil)
	if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "/setup" {
		t.Errorf("GET / returned HTTP %d redirecting to %q, want 303 to /setup", redirect.Code, redirect.Header().Get("Location"))
	}

	page := setupRequest(h, "/setup", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("GET /setup returned HTTP %d", page.Code)
	}
	assertPageHeaders(t, page.Result(), "en")
	assertContains(t, page.Body.String(), `action="/setup/check"`, `name="rev" value="`+Revision(cfg)+`"`,
		"Subscription link", "device slot")
}

func TestSetupViewRoleCannotSubmit(t *testing.T) {
	cfg := &model.Config{Subscriptions: []subscription.Source{{ID: "sample", URL: setupTestURL}}}
	deps := &setupFixture{cfg: cfg}
	h := New(deps, setupTestOptions(RoleView))
	page := setupRequest(h, "/setup", nil)
	if page.Code != http.StatusOK {
		t.Errorf("view GET /setup returned HTTP %d", page.Code)
	} else {
		assertContains(t, page.Body.String(), "View only", "Replace link", `name="url"`, "required disabled", `type="submit" disabled`)
	}
	for _, path := range []string{"/setup/check", "/setup/enable"} {
		post := setupRequest(h, path, url.Values{"rev": {Revision(cfg)}, "url": {setupTestURL}})
		if post.Code != http.StatusForbidden {
			t.Errorf("view POST %s returned HTTP %d, want 403", path, post.Code)
		}
		if strings.Contains(post.Body.String(), "synthetic-token") {
			t.Errorf("view POST %s disclosed the supplied link", path)
		}
	}
	if strings.Contains(page.Body.String(), "synthetic-token") {
		t.Error("view GET /setup disclosed the configured link")
	}
	if deps.checks != 0 || deps.applies != 0 {
		t.Fatal("view role reached the preview or Apply")
	}
}

func TestSetupCheckStates(t *testing.T) {
	expires := time.Now().Add(53 * 24 * time.Hour).Unix()
	active := subscription.Metadata{
		Title: "Test provider", Announce: "Scheduled maintenance",
		Usage: &subscription.Usage{Total: 200 << 30, Expire: expires},
	}
	for _, tc := range []struct {
		name, url string
		preview   SetupPreview
		status    int
		ready     bool
		want      []string
	}{
		{
			name: "ready", url: setupTestURL, status: http.StatusOK, ready: true,
			preview: SetupPreview{
				State: subscription.StateReady, Metadata: active, NodeCount: 2, NodeNames: []string{"Node A", "Node B"},
				RulesState: "pending",
				Routing: &subscription.RoutingSummary{
					Name: "Example routing", GlobalProxy: true,
					Direct: subscription.RoutingActionSummary{Sites: subscription.RoutingListSummary{Count: 2, Categories: []string{"ru"}}},
				},
			},
			want: []string{"Test provider", "Active", "0 of 200 GB", "2: Node A, Node B", "Example routing", "Sites: 2", "ru", "Scheduled maintenance",
				"Provider profile default: through the VPN.", "Provider rules are pending evaluation.", "KeenProxy evaluates these rules when you enable the subscription."},
		},
		{
			name: "withheld", url: setupTestURL, status: http.StatusOK, ready: true,
			preview: SetupPreview{State: subscription.StateReady, NodeCount: 1, RulesState: "withheld"},
			want:    []string{"The provider does not supply routing rules.", "The Home policy uses the subscription as its default."},
		},
		{
			name: "malformed profile", url: setupTestURL, status: http.StatusOK, ready: true,
			preview: SetupPreview{State: subscription.StateReady, NodeCount: 1, RulesState: "failed"},
			want:    []string{"The provider routing rules could not be read."},
		},
		{
			name: "device limit", url: setupTestURL, status: http.StatusOK,
			preview: SetupPreview{
				State:    subscription.StateHWIDLimit,
				Metadata: subscription.Metadata{Title: "Test provider", ProfileURL: "https://provider.example/account"},
			},
			want: []string{"Device limit", "All device slots", "Personal account", `href="https://provider.example/account"`},
		},
		{
			name: "expired", url: setupTestURL, status: http.StatusOK,
			preview: SetupPreview{State: subscription.StateHTTPError, Metadata: subscription.Metadata{
				Usage: &subscription.Usage{Expire: time.Date(2025, 1, 15, 12, 0, 0, 0, time.Local).Unix()},
			}},
			want: []string{"Expired", "The subscription expired on January 15, 2025."},
		},
		{
			name: "unreachable", url: setupTestURL, status: http.StatusOK,
			preview: SetupPreview{State: subscription.StateNetworkError},
			want:    []string{"Could not check the subscription."},
		},
		{
			name: "provider error", url: setupTestURL, status: http.StatusOK,
			preview: SetupPreview{State: subscription.StateHTTPError},
			want:    []string{"Could not check the subscription."},
		},
		{
			name: "invalid URL", url: "http://provider.example/synthetic-token", status: http.StatusBadRequest,
			want: []string{"Enter a valid HTTPS subscription link."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := &setupFixture{cfg: &model.Config{}, preview: tc.preview}
			h := New(deps, setupTestOptions(RoleManage))
			w := setupRequest(h, "/setup/check", url.Values{"rev": {setupFormRevision(t, h)}, "url": {tc.url}})
			if w.Code != tc.status {
				t.Fatalf("check HTTP %d, want %d", w.Code, tc.status)
			}
			assertPageHeaders(t, w.Result(), "en")
			body := w.Body.String()
			assertContains(t, body, tc.want...)
			if hasEnable := strings.Contains(body, `action="/setup/enable"`); hasEnable != tc.ready {
				t.Errorf("enable form present %t, want %t", hasEnable, tc.ready)
			}
			if tc.ready {
				if strings.Contains(body, "synthetic-token") {
					t.Error("successful preview revealed the submitted link")
				}
				formField(t, body, "preview")
			} else {
				assertContains(t, body, `value="`+tc.url+`"`)
				if strings.Count(body, "synthetic-token") != 1 {
					t.Error("failed check must echo the link only once")
				}
			}
			if tc.name == "invalid URL" {
				if deps.checks != 0 {
					t.Error("invalid input reached provider preview")
				}
			} else if deps.checks != 1 || deps.source != (subscription.Source{ID: "main", URL: tc.url, SendHWID: true}) {
				t.Errorf("preview used the wrong source or number of calls: %d", deps.checks)
			}
			if deps.applies != 0 || len(deps.cfg.Subscriptions) != 0 {
				t.Error("check applied a configuration")
			}
		})
	}
}

func TestSetupEscapesProviderStrings(t *testing.T) {
	deps := &setupFixture{
		cfg: &model.Config{},
		preview: SetupPreview{
			State: subscription.StateReady, NodeCount: 1, NodeNames: []string{`<node>"`},
			Metadata: subscription.Metadata{Title: `<title>"`, Announce: `<script>alert(1)</script>`},
			Routing: &subscription.RoutingSummary{
				Name: "<routing>",
				Block: subscription.RoutingActionSummary{Sites: subscription.RoutingListSummary{
					Count: 1, Categories: []string{`<rule>"`},
				}},
			},
		},
	}
	h := New(deps, setupTestOptions(RoleManage))
	w := setupRequest(h, "/setup/check", url.Values{"rev": {setupFormRevision(t, h)}, "url": {setupTestURL}})
	if w.Code != http.StatusOK {
		t.Fatalf("check HTTP %d", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "&lt;title&gt;&#34;", "&lt;script&gt;alert(1)&lt;/script&gt;",
		"&lt;node&gt;&#34;", "&lt;routing&gt;", "&lt;rule&gt;&#34;")
	for _, raw := range []string{"<node>", "<routing>", "<rule>", "<script>alert(1)", "style="} {
		if strings.Contains(body, raw) {
			t.Errorf("unsafe markup %q in preview", raw)
		}
	}
}

func TestSetupEnableFirstRunAndFlash(t *testing.T) {
	deps := &setupFixture{
		cfg:     &model.Config{LAN: model.LAN{Interface: "test-lan"}},
		lan:     netip.MustParsePrefix("192.168.7.1/24"),
		preview: SetupPreview{State: subscription.StateReady, NodeCount: 1},
	}
	h := New(deps, setupTestOptions(RoleManage))
	form := checkSetupLink(t, h)
	w := setupRequest(h, "/setup/enable", form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("enable HTTP %d redirecting to %q", w.Code, w.Header().Get("Location"))
	}
	if deps.applies != 1 || deps.lanInterface != "test-lan" {
		t.Fatalf("Apply calls %d, interface %q", deps.applies, deps.lanInterface)
	}
	want := &model.Config{
		LAN:           model.LAN{Interface: "test-lan"},
		Subscriptions: []subscription.Source{{ID: "main", URL: setupTestURL, SendHWID: true}},
		Networks: []model.Network{{
			Name: "Home", CIDR: "192.168.7.0/24", Mode: model.ModeSplit,
			Target: "subscription:main:auto", Default: model.DefaultProfile,
		}},
		ProviderRules: &model.ProviderRulesSettings{Source: "main"},
	}
	if !reflect.DeepEqual(deps.cfg, want.Clone()) {
		t.Fatal("first enable did not apply the expected Home network and provider settings")
	}
	if strings.Contains(w.Body.String()+w.Header().Get("Set-Cookie"), "synthetic-token") {
		t.Error("enable disclosed the subscription link")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("enable returned %d flash cookies, want 1", len(cookies))
	}
	r.AddCookie(cookies[0])
	home := httptest.NewRecorder()
	h.ServeHTTP(home, r)
	if home.Code != http.StatusOK {
		t.Fatalf("GET / after enable returned HTTP %d", home.Code)
	}
	assertContains(t, home.Body.String(), "Settings saved")
	if cleared := home.Result().Cookies(); len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatal("overview did not consume the flash")
	}
}

func TestSetupEnableExistingPreservesConfiguration(t *testing.T) {
	cfg := &model.Config{
		Paused: true,
		LAN:    model.LAN{Interface: "lan"},
		Subscriptions: []subscription.Source{
			{ID: "keep-id", URL: "https://provider.example/old-link", Fallback: "direct"},
			{ID: "reserve", URL: "https://provider.example/reserve"},
		},
		Clients: []model.Client{{Name: "Laptop", MAC: "02:00:00:00:00:03", Mode: model.ModeOff}},
		Groups:  []model.Group{{Name: "Custom", Target: "subscription:keep-id:auto", Entries: []string{"example.net"}}},
		Networks: []model.Network{{
			Name: "Existing", CIDR: "192.168.12.0/24", Mode: model.ModeSplit,
			Target: "subscription:keep-id:auto", Default: model.TargetDirect,
		}},
		ProviderRules: &model.ProviderRulesSettings{Source: "keep-id", Disabled: []string{"proxy:geosite:video"}},
	}
	deps := &setupFixture{
		cfg: cfg, lanErr: errors.New("missing LAN"),
		preview: SetupPreview{
			State: subscription.StateReady, NodeCount: 1, RulesState: "pending",
			Routing: &subscription.RoutingSummary{Name: "Provider profile", GlobalProxy: true},
		},
	}
	h := New(deps, setupTestOptions(RoleManage))
	initial := setupRequest(h, "/setup", nil)
	assertContains(t, initial.Body.String(), "<h1>Replace link</h1>")
	if strings.Contains(initial.Body.String(), "old-link") {
		t.Error("replacement form disclosed the current subscription link")
	}
	rev := setupFormRevision(t, h)
	checked := setupRequest(h, "/setup/check", url.Values{"rev": {rev}, "url": {setupTestURL}})
	if checked.Code != http.StatusOK {
		t.Fatalf("replacement check HTTP %d", checked.Code)
	}
	body := checked.Body.String()
	assertContains(t, body, "Provider profile default: through the VPN.", "Replacing the link keeps your saved routing mode.",
		"KeenProxy evaluates these rules when you replace the link.")
	form := url.Values{"rev": {rev}, "preview": {formField(t, body, "preview")}}
	if deps.source.ID != "keep-id" {
		t.Error("replacement preview did not use the saved subscription ID")
	}
	w := setupRequest(h, "/setup/enable", form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("replace returned HTTP %d", w.Code)
	}
	want := cfg.Clone()
	want.Subscriptions[0].URL, want.Subscriptions[0].SendHWID = setupTestURL, true
	if deps.lanLookups != 0 || deps.applies != 1 || !reflect.DeepEqual(deps.cfg, want) {
		t.Fatal("replacing the link touched other configuration or looked up the LAN")
	}
}

func TestOverviewAddsSubscriptionWithoutReplacingNetworks(t *testing.T) {
	f := newOverviewFixture()
	f.cfg.Subscriptions, f.cfg.ProviderRules, f.subs = nil, nil, nil
	f.cfg.Networks[0].Target, f.cfg.Networks[0].Default = "backup", "backup"
	f.cfg.Groups[0].Target = "backup"
	f.setupFixture.preview = SetupPreview{State: subscription.StateReady, NodeCount: 1}
	f.lanErr = errors.New("LAN discovery should be unnecessary")
	want := f.Config()
	want.Subscriptions = []subscription.Source{{ID: "main", URL: setupTestURL, SendHWID: true}}
	h := New(f, setupTestOptions(RoleManage))
	assertContains(t, setupRequest(h, "/", nil).Body.String(), `href="/setup">Set up subscription</a>`)
	setup := setupRequest(h, "/setup", nil)
	assertContains(t, setup.Body.String(), "Add subscription")
	rev := formField(t, setup.Body.String(), "rev")
	checked := setupRequest(h, "/setup/check", url.Values{"rev": {rev}, "url": {setupTestURL}})
	assertContains(t, checked.Body.String(), "Add subscription", "Adding the subscription keeps your saved routing mode.")
	if strings.Contains(checked.Body.String(), "The Home policy uses the subscription as its default.") {
		t.Error("adding a subscription promised to change the default route")
	}
	post := setupRequest(h, "/setup/enable", url.Values{"rev": {rev}, "preview": {formField(t, checked.Body.String(), "preview")}})
	if post.Code != http.StatusSeeOther || post.Header().Get("Location") != "/" || f.lanLookups != 0 || f.applies != 1 || !reflect.DeepEqual(f.Config(), want.Clone()) {
		t.Fatalf("adding to existing policies returned HTTP %d with %d LAN lookups and %d applies", post.Code, f.lanLookups, f.applies)
	}
}

func TestOverviewOpensForNetworkOnlyConfig(t *testing.T) {
	f := &overviewFixture{setupFixture: setupFixture{cfg: &model.Config{
		Networks: []model.Network{{Name: "Home", CIDR: "192.0.2.0/24", Mode: model.ModeFull, Target: model.TargetDirect}},
	}}}
	page := setupRequest(New(f, setupTestOptions(RoleManage)), "/", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("network-only configuration returned HTTP %d with Location %q", page.Code, page.Header().Get("Location"))
	}
	assertContains(t, page.Body.String(), "No subscription configured.")
}

func TestSetupEnableWithNoLANOrPreview(t *testing.T) {
	deps := &setupFixture{
		cfg:     &model.Config{},
		lanErr:  errors.New("private detail: " + setupTestURL),
		preview: SetupPreview{State: subscription.StateReady, NodeCount: 1},
	}
	h := New(deps, setupTestOptions(RoleManage))
	forged := setupRequest(h, "/setup/enable", url.Values{
		"rev": {setupFormRevision(t, h)}, "url": {setupTestURL}, "preview": {"forged"},
	})
	if forged.Code != http.StatusConflict || deps.lanLookups != 0 {
		t.Fatalf("enable without a preview returned HTTP %d and made %d LAN lookups", forged.Code, deps.lanLookups)
	}
	form := checkSetupLink(t, h)
	refused := setupRequest(h, "/setup/enable", form)
	if refused.Code != http.StatusUnprocessableEntity {
		t.Fatalf("enable without LAN returned HTTP %d", refused.Code)
	}
	assertContains(t, refused.Body.String(), "Could not find the home network.")
	if deps.applies != 0 || strings.Contains(refused.Body.String(), "synthetic-token") || len(deps.cfg.Subscriptions) != 0 {
		t.Error("enable without LAN applied or disclosed the subscription link")
	}
}

func TestSetupRejectsStaleCheckAndEnable(t *testing.T) {
	deps := &setupFixture{cfg: &model.Config{}, preview: SetupPreview{State: subscription.StateReady, NodeCount: 1}}
	h := New(deps, setupTestOptions(RoleManage))
	form := checkSetupLink(t, h)
	deps.cfg.Paused = true
	stale := setupRequest(h, "/setup/check", url.Values{"rev": form["rev"], "url": {setupTestURL}})
	if stale.Code != http.StatusConflict || deps.checks != 1 {
		t.Fatalf("stale check returned HTTP %d after %d preview calls", stale.Code, deps.checks)
	}
	refused := setupRequest(h, "/setup/enable", form)
	if refused.Code != http.StatusConflict {
		t.Fatalf("stale enable returned HTTP %d", refused.Code)
	}
	assertContains(t, refused.Body.String(), "Settings changed in another window",
		`name="rev" value="`+Revision(deps.Config())+`"`)
	form.Set("rev", setupFormRevision(t, h))
	rebound := setupRequest(h, "/setup/enable", form)
	if rebound.Code != http.StatusConflict || deps.applies != 0 || deps.lanLookups != 0 || strings.Contains(refused.Body.String(), "synthetic-token") {
		t.Fatal("a stale or rebound preview reached Apply or disclosed its link")
	}
}

func TestSetupEnableTokenBelongsToManagerAndIsSingleUse(t *testing.T) {
	deps := &setupFixture{
		cfg:     &model.Config{Subscriptions: []subscription.Source{{ID: "sample", URL: setupTestURL, SendHWID: true}}},
		preview: SetupPreview{State: subscription.StateReady, NodeCount: 1},
	}
	opts := setupTestOptions(RoleManage)
	manager := "first manager"
	opts.User = func(*http.Request) string { return manager }
	h := New(deps, opts)
	form := checkSetupLink(t, h)
	manager = "second manager"
	if w := setupRequest(h, "/setup/enable", form); w.Code != http.StatusConflict || deps.applies != 0 {
		t.Fatal("another account could use the checked link")
	}
	manager = "first manager"
	if w := setupRequest(h, "/setup/enable", form); w.Code != http.StatusSeeOther || deps.applies != 1 {
		t.Fatalf("the owner could not enable the checked link: HTTP %d", w.Code)
	}
	// Replacing the same URL leaves the revision current. Replay must still
	// require a fresh check.
	if w := setupRequest(h, "/setup/enable", form); w.Code != http.StatusConflict || deps.applies != 1 {
		t.Fatal("a second submission reused a consumed preview")
	}
}

func TestSetupReplacementPreservesDisabledProviderRules(t *testing.T) {
	cfg := &model.Config{
		Subscriptions: []subscription.Source{{ID: "sample", URL: "https://provider.example/old-link"}},
		ProviderRules: &model.ProviderRulesSettings{Source: "sample", Off: true, Disabled: []string{"proxy:geosite:video"}},
		Networks: []model.Network{{
			Name: "Home", CIDR: "192.168.7.0/24", Mode: model.ModeSplit,
			Target: "subscription:sample:auto", Default: model.TargetDirect,
		}},
	}
	deps := &setupFixture{cfg: cfg, preview: SetupPreview{
		State: subscription.StateReady, NodeCount: 1, RulesState: "pending",
		Routing: &subscription.RoutingSummary{Name: "Provider profile", GlobalProxy: true},
	}}
	h := New(deps, setupTestOptions(RoleManage))
	w := setupRequest(h, "/setup/check", url.Values{"rev": {setupFormRevision(t, h)}, "url": {setupTestURL}})
	if w.Code != http.StatusOK {
		t.Fatalf("replacement check HTTP %d", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "Provider profile default: through the VPN.", "Replacing the link keeps your saved routing mode.")
	if strings.Contains(body, "KeenProxy evaluates these rules") || strings.Contains(body, "Traffic that matches no rule goes through the VPN") {
		t.Fatal("preview promised to change a saved direct default or enable provider rules")
	}
}

func TestSetupEnableRequiresFreshCheckForObsoletePreview(t *testing.T) {
	deps := &setupFixture{
		cfg:     &model.Config{},
		lan:     netip.MustParsePrefix("192.168.7.1/24"),
		preview: SetupPreview{State: subscription.StateReady, NodeCount: 1},
	}
	h := New(deps, setupTestOptions(RoleManage))
	form := checkSetupLink(t, h)
	deps.preview.Metadata.Usage = &subscription.Usage{Expire: time.Now().Add(-time.Minute).Unix()}
	next := setupRequest(h, "/setup/check", url.Values{"rev": {form.Get("rev")}, "url": {setupTestURL}})
	assertContains(t, next.Body.String(), "Expired")
	older := setupRequest(h, "/setup/enable", form)
	if older.Code != http.StatusConflict || deps.applies != 0 || len(deps.cfg.Subscriptions) != 0 {
		t.Fatalf("obsolete preview returned HTTP %d with %d writes", older.Code, deps.applies)
	}
	assertContains(t, older.Body.String(), "Check the subscription link again before saving.")
	if strings.Contains(older.Body.String(), "synthetic-token") {
		t.Fatal("obsolete preview response disclosed the link")
	}
}

func TestSetupEnableReportsAppliedButUnsaved(t *testing.T) {
	deps := &setupFixture{
		cfg:     &model.Config{},
		lan:     netip.MustParsePrefix("192.168.7.1/24"),
		preview: SetupPreview{State: subscription.StateReady, NodeCount: 1},
		saveErr: &model.AppliedUnsavedError{Err: errors.New("failed write " + setupTestURL)},
	}
	h := New(deps, setupTestOptions(RoleManage))
	form := checkSetupLink(t, h)
	w := setupRequest(h, "/setup/enable", form)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("enable with failed persistence returned HTTP %d", w.Code)
	}
	assertPageHeaders(t, w.Result(), "en")
	body := w.Body.String()
	assertContains(t, body, "The new settings are active.", "A restart may restore the previous saved settings.")
	if len(deps.cfg.Subscriptions) != 1 || formField(t, body, "rev") != Revision(deps.Config()) ||
		Revision(deps.Config()) == form.Get("rev") || strings.Contains(body, "synthetic-token") ||
		strings.Contains(body, "Check the link again and retry") || w.Header().Get("Location") != "" {
		t.Fatal("save failure did not report the current, unsaved configuration safely")
	}
}

type setupFixture struct {
	Deps
	cfg                         *model.Config
	preview                     SetupPreview
	source                      subscription.Source
	lan                         netip.Prefix
	lanErr                      error
	saveErr                     error
	lanInterface                string
	checks, applies, lanLookups int
}

func (f *setupFixture) Config() *model.Config { return f.cfg.Clone() }

func (*setupFixture) OverviewStatus() OverviewStatus       { return OverviewStatus{} }
func (*setupFixture) Subscriptions() []AppliedSubscription { return nil }
func (*setupFixture) ProviderRules() RoutingRules          { return RoutingRules{} }
func (*setupFixture) TrafficSeries() []stats.Point         { return nil }

func (f *setupFixture) PreviewSubscription(_ context.Context, source subscription.Source) SetupPreview {
	f.checks++
	f.source = source
	preview := f.preview
	preview.PreviewID = uint64(f.checks)
	return preview
}

func (f *setupFixture) LANPrefix(iface string) (netip.Prefix, error) {
	f.lanLookups++
	f.lanInterface = iface
	return f.lan, f.lanErr
}

func (f *setupFixture) Apply(_ context.Context, cfg *model.Config, rev string) error {
	f.applies++
	if rev != Revision(f.Config()) {
		return errors.New("unexpected revision in Apply")
	}
	f.cfg = cfg.Clone()
	return f.saveErr
}

func (f *setupFixture) ApplySubscriptionPreview(ctx context.Context, cfg *model.Config, rev string, checked subscription.PreviewRef) error {
	if checked.ID != uint64(f.checks) || checked.Source != f.source {
		return subscription.ErrPreviewChanged
	}
	return f.Apply(ctx, cfg, rev)
}

func checkSetupLink(t *testing.T, h http.Handler) url.Values {
	t.Helper()
	rev := setupFormRevision(t, h)
	w := setupRequest(h, "/setup/check", url.Values{"rev": {rev}, "url": {setupTestURL}})
	if w.Code != http.StatusOK {
		t.Fatalf("check HTTP %d", w.Code)
	}
	return url.Values{"rev": {rev}, "preview": {formField(t, w.Body.String(), "preview")}}
}

func setupFormRevision(t *testing.T, h http.Handler) string {
	t.Helper()
	w := setupRequest(h, "/setup", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /setup HTTP %d", w.Code)
	}
	return formField(t, w.Body.String(), "rev")
}

func formField(t *testing.T, body string, name string) string {
	t.Helper()
	match := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("form field %q missing", name)
	}
	return match[1]
}

func setupTestOptions(role Role) Options {
	return Options{
		Role: func(*http.Request) Role { return role },
		User: func(*http.Request) string { return "operator" },
	}
}

func setupRequest(h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	if form == nil {
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(w, r)
	return w
}
