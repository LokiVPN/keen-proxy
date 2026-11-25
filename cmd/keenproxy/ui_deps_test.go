package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/geodata"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

func TestWizardValidationCompilesDisabledReplacement(t *testing.T) {
	cfg := &model.Config{}
	cfg.Defaults()
	cfg.Connections = []model.Connection{{
		ID: "retired", Type: model.ConnSingBox, Disabled: true,
		Outbound: map[string]any{"type": "socks", "server": "vpn.example.test", "server_port": 1080},
	}}
	deps := uiDeps{daemon: &wizardRuntimeDaemon{}}
	if err := deps.ValidateConnection(context.Background(), cfg, "retired"); err != nil {
		t.Fatal(err)
	}
	const sensitive = "synthetic-private-protocol"
	cfg.Connections[0].Outbound["type"] = sensitive
	err := deps.ValidateConnection(context.Background(), cfg, "retired")
	if err == nil || strings.Contains(err.Error(), sensitive) || !cfg.Connections[0].Disabled {
		t.Fatal("profile validation failed to reject the disabled candidate privately without changing its switch")
	}
}

func TestWizardValidationAcceptsUnchangedDormantProfile(t *testing.T) {
	cfg := &model.Config{Connections: []model.Connection{
		{ID: "retired", Disabled: true, Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "vless", "server": "old.example.test", "server_port": 443,
		}},
		{ID: "new", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "socks", "server": "vpn.example.test", "server_port": 1080,
		}},
	}}
	cfg.Defaults()
	deps := uiDeps{daemon: &wizardRuntimeDaemon{}}
	if err := deps.ValidateConnection(context.Background(), cfg, "new"); err != nil {
		t.Fatalf("dormant profile blocked an unrelated change: %v", err)
	}
	if err := deps.ValidateConnection(context.Background(), cfg, "retired"); err == nil {
		t.Fatal("replacing the dormant entry skipped its own field checks")
	}
}

type wizardRuntimeDaemon struct {
	managementDaemon
	cfg     *model.Config
	applies int
}

func (d *wizardRuntimeDaemon) Config() *model.Config { return d.cfg.Clone() }

func (d *wizardRuntimeDaemon) ApplyIfCurrent(_ context.Context, cfg *model.Config, rev string) error {
	if rev != ui.Revision(d.Config()) {
		return model.ErrConfigChanged
	}
	d.applies++
	d.cfg = cfg.Clone()
	return nil
}

func (*wizardRuntimeDaemon) CompileConnectionDraft(cfg *model.Config) (compile.Output, error) {
	return compile.Compile(compile.Input{Config: cfg})
}

func TestWizardRuntimeValidationCheckAndSave(t *testing.T) {
	d := &wizardRuntimeDaemon{cfg: &model.Config{Connections: []model.Connection{
		{ID: "home", Type: model.ConnLink, Link: "socks5://home.example:1080", Fallback: model.TargetDirect},
		{ID: "home-2", Type: model.ConnLink, Link: "socks5://other.example:1080", Fallback: model.TargetDirect},
	}}}
	d.cfg.Defaults()
	h := ui.New(uiDeps{daemon: d}, ui.Options{Role: func(*http.Request) ui.Role { return ui.RoleManage }})
	post := func(path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	check := func(profile string) *httptest.ResponseRecorder {
		return post("/connections/new/check", url.Values{"rev": {ui.Revision(d.Config())}, "method": {"paste"}, "profile": {profile}})
	}
	const profile = `{"type":"socks","server":"vpn.example.test","server_port":1080`
	w := check(profile + `,"tag":"Failover Home"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="id" value="failover-home-3"`) {
		t.Errorf("Check did not offer an ID distinct from both generated tags: HTTP %d", w.Code)
	}
	const missing = "synthetic-absent-detour"
	for _, raw := range []string{
		profile + `,"detour":"` + missing + `"}`,
		profile + `,"tag":"Cycle","detour":"cycle"}`,
	} {
		w := check(raw)
		if w.Code != http.StatusUnprocessableEntity || strings.Contains(w.Body.String(), missing) {
			t.Errorf("invalid graph was accepted or its error was exposed: HTTP %d", w.Code)
		}
	}
	const wireGuard = `{"endpoint":{"type":"wireguard","address":["10.1.0.2/32"],"private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","peers":[{"address":"192.0.2.10","port":51820,"public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","allowed_ips":["0.0.0.0/0"]}],"detour":"direct"}}`
	for _, raw := range []string{wireGuard, profile + `,"detour":"block"}`, profile + `,"detour":"failover-home"}`,
		profile + `,"bind_interface":"synthetic-device"}`, profile + `,"inet4_bind_address":"192.0.2.10"}`} {
		refused := check(raw)
		if refused.Code != http.StatusUnprocessableEntity || !strings.Contains(refused.Body.String(), "includes unsupported routing options") ||
			strings.Contains(refused.Body.String(), "synthetic-device") || d.applies != 0 {
			t.Errorf("Check did not refuse explicit routing before Apply: HTTP %d", refused.Code)
		}
	}
	checked := check(profile + `,"tag":"Office","detour":"home"}`)
	if checked.Code != http.StatusOK {
		t.Fatalf("a valid manual connection dependency failed Check: HTTP %d", checked.Code)
	}
	token := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		m := regexp.MustCompile(`name="preview" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
		if m == nil {
			t.Fatal("a valid draft was not available")
		}
		return html.UnescapeString(m[1])
	}
	cookies := checked.Result().Cookies()
	form := url.Values{
		"rev": {ui.Revision(d.Config())}, "preview": {token(checked)}, "name": {"Office"}, "id": {"failover-home"},
	}
	w = post("/connections/new/save", form, cookies...)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "conflicts with a routing tag") ||
		!strings.Contains(w.Body.String(), `aria-describedby="wizard-id-hint wizard-id-error"`) || d.applies != 0 {
		t.Fatalf("Save did not associate the generated-tag collision with its editable ID: HTTP %d", w.Code)
	}
	form.Set("id", "office")
	form.Set("preview", token(w))
	if saved := post("/connections/new/save", form, cookies...); saved.Code != http.StatusSeeOther || d.applies != 1 {
		t.Fatalf("corrected ID failed Save: HTTP %d", saved.Code)
	}
}

func TestDevicesPageUsesDaemonDiscovery(t *testing.T) {
	deps := uiDeps{daemon: deviceSnapshotDaemon{
		cfg: &model.Config{Networks: []model.Network{{Name: "Home", CIDR: "192.0.2.0/24", Mode: model.ModeSplit}}},
	}}
	h := ui.New(deps, ui.Options{Role: func(*http.Request) ui.Role { return ui.RoleManage }})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/devices", nil))
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Published laptop") || !strings.Contains(body, "192.0.2.20") ||
		!strings.Contains(body, `name="split" value="02:00:00:00:00:20" checked`) || strings.Contains(body, "Old config name") {
		t.Fatalf("devices page did not use the daemon discovery snapshot, HTTP %d", w.Code)
	}
}

type deviceSnapshotDaemon struct {
	managementDaemon
	cfg *model.Config
}

func (d deviceSnapshotDaemon) Config() *model.Config { return d.cfg.Clone() }

func (deviceSnapshotDaemon) Devices() []daemon.Device {
	return []daemon.Device{{
		MAC: "02:00:00:00:00:20", IP: "192.0.2.20", Hostname: "Published laptop", HostnameSource: "dhcp",
		Client: "Old config name", Mode: model.ModeOff,
	}}
}

func TestConnectionsAdapterUsesDaemonCatalogAndChecks(t *testing.T) {
	const source, node = "sample", "aabbccddeeff00112233445566778899"
	d := &connectionCheckDaemon{}
	h := ui.New(uiDeps{daemon: d}, ui.Options{Role: func(*http.Request) ui.Role { return ui.RoleManage }})
	revision := ui.Revision(d.Config())
	form := url.Values{"rev": {revision}, "check": {source + ":" + node}, "fallback.sample": {""}, "fallback.other": {""}}
	r := httptest.NewRequest(http.MethodPost, "/connections", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || d.check != [3]string{source, node, revision} {
		t.Fatalf("check = HTTP %d, daemon arguments %v", w.Code, d.check)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/fragments/connections/"+source, nil))
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Checking") || !strings.Contains(body, "Unsupported entries skipped: 1") ||
		!strings.Contains(body, "Check all nodes") || strings.Contains(body, "private-probe-detail") {
		t.Fatalf("fragment did not project the daemon's safe check state, HTTP %d", w.Code)
	}
}

func TestConnectionsShowsSelectedSubscriptionRuleState(t *testing.T) {
	for _, tc := range []struct {
		state daemon.ProviderRulesState
		copy  string
	}{
		{daemon.ProviderRulesPending, "Provider rules are pending evaluation."},
		{daemon.ProviderRulesWithheld, "The provider does not supply routing rules."},
		{daemon.ProviderRulesFailed, "Provider routing rules could not be loaded."},
		{daemon.ProviderRulesPartial, "Some provider routing rules are unavailable."},
	} {
		t.Run(string(tc.state), func(t *testing.T) {
			h := ui.New(uiDeps{daemon: &connectionCheckDaemon{rulesState: tc.state}}, ui.Options{Role: func(*http.Request) ui.Role { return ui.RoleView }})
			for _, path := range []string{"/connections", "/fragments/connections/sample"} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				if body := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(body, "Ready") || !strings.Contains(body, tc.copy) {
					t.Errorf("%s = HTTP %d, expected a ready catalog and %q", path, w.Code, tc.copy)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/fragments/connections/other", nil))
			if w.Code != http.StatusOK || strings.Contains(w.Body.String(), tc.copy) {
				t.Errorf("unselected subscription got HTTP %d or inherited the selected source's notice", w.Code)
			}
		})
	}
}

type connectionCheckDaemon struct {
	managementDaemon
	check      [3]string
	rulesState daemon.ProviderRulesState
}

func (*connectionCheckDaemon) Config() *model.Config {
	return &model.Config{
		Subscriptions: []subscription.Source{{ID: "sample", URL: "https://provider.example/catalog"}, {ID: "other", URL: "https://secondary.example/catalog"}},
		ProviderRules: &model.ProviderRulesSettings{Source: "sample"},
	}
}

func (*connectionCheckDaemon) RoutingStatus() daemon.RoutingStatus { return daemon.RoutingStatus{} }

func (*connectionCheckDaemon) ProviderRules() (compile.ProviderRules, *model.ProviderRulesSettings, daemon.ProviderRulesState) {
	return compile.ProviderRules{}, nil, daemon.ProviderRulesOff
}

func (d *connectionCheckDaemon) CheckSubscriptionIfCurrent(source, node, revision string) error {
	d.check = [3]string{source, node, revision}
	return nil
}

func (d *connectionCheckDaemon) Subscriptions() []daemon.SubscriptionStatus {
	return []daemon.SubscriptionStatus{{
		ID: "sample", State: subscription.StateReady, Skipped: 1, RulesState: d.rulesState,
		Nodes: []daemon.SubscriptionNodeStatus{{ID: d.check[1], Name: "North", Checking: true, CheckError: "private-probe-detail"}},
	}, {ID: "other", State: subscription.StateReady}}
}

func TestRoutingRulesProjection(t *testing.T) {
	rules := compile.BuildProviderRules(&subscription.RoutingProfile{
		RouteOrder: "block-direct-proxy", GlobalProxy: true,
		DirectSites: []string{"domain:a.example", "full:b.example", "literal", "regexp:^c"},
		DirectIP:    []string{"geoip:private", "192.0.2.0/24"},
		ProxySites:  []string{"geosite:youtube"},
	}, nil, nil, nil)
	deps := uiDeps{daemon: routingSnapshotDaemon{rules: rules}}
	got := deps.ProviderRules()
	want := ui.RoutingRules{
		Source: "fixture", State: "partial", HasProfile: true, GlobalProxy: true,
		Rules: []ui.RoutingRule{
			{Key: "direct:literals:site", Action: "direct", Kind: "site", Source: "literals", LiteralCount: 4},
			{Key: "direct:literals:ip", Action: "direct", Kind: "ip", Source: "literals", LiteralCount: 1},
			{Key: "proxy:geosite:youtube", Action: "proxy", Kind: "site", Source: "geosite:youtube", Unavailable: "provider sent no geosite file"},
		},
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("routing projection = %+v, want %+v", got, want)
	}
}

func TestRoutingHTMLRedactsProviderRuleKeysAndLabels(t *testing.T) {
	const token = "routing-fixture-token"
	source := subscription.Source{ID: "fixture", URL: "https://provider.example/private?key=" + token, SendHWID: true}
	var hwid string
	transport := routingRoundTrip(func(r *http.Request) (*http.Response, error) {
		hwid = r.Header.Get("X-HWID")
		profile, err := json.Marshal(map[string]any{
			"Geositeurl": "https://data.example/geosite.dat",
			"ProxySites": []string{"geosite:https://other.example/?nested=" + url.QueryEscape(source.URL), "geosite:device-" + hwid},
			"BlockSites": []string{"geosite:" + source.URL},
		})
		if err != nil {
			t.Fatal(err)
		}
		header := make(http.Header)
		header.Set("routing", "happ://routing/add/"+base64.StdEncoding.EncodeToString(profile))
		return &http.Response{
			StatusCode: http.StatusOK, Header: header,
			Body: io.NopCloser(strings.NewReader("socks5://fixture.example:1080#Fixture")),
		}, nil
	})
	fetcher := subscription.NewFetcher(filepath.Join(t.TempDir(), "identity"), transport)
	result := fetcher.Fetch(t.Context(), source)
	if result.State != subscription.StateReady || result.Routing == nil || hwid == "" {
		t.Fatalf("synthetic routing fixture did not load: %s", result.State)
	}
	sites := make(map[string]geodata.Sites)
	for _, entry := range result.Routing.ProxySites {
		sites[strings.TrimPrefix(entry, "geosite:")] = geodata.Sites{Suffix: []string{"rule.example"}}
	}
	rules := compile.BuildProviderRules(result.Routing, sites, nil, nil)
	cfg := &model.Config{Subscriptions: []subscription.Source{source}}
	cfg.RouteHomeThroughSubscription(source.ID, netip.MustParsePrefix("192.0.2.0/24"))
	deps := uiDeps{daemon: routingSnapshotDaemon{rules: rules, cfg: cfg}}
	for _, role := range []ui.Role{ui.RoleManage, ui.RoleView} {
		h := ui.New(deps, ui.Options{Role: func(*http.Request) ui.Role { return role }})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/routing", nil))
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Fatalf("routing rendered HTTP %d for role %v", w.Code, role)
		}
		if strings.Contains(body, token) || strings.Contains(body, hwid) || strings.Contains(body, "provider.example") {
			t.Errorf("routing HTML for role %v disclosed subscription data", role)
		}
		if !strings.Contains(body, "[redacted]") {
			t.Errorf("routing HTML for role %v omitted its redacted label", role)
		}
		keys := regexp.MustCompile(`name="rule" value="([^"]+)"`).FindAllStringSubmatch(body, -1)
		if len(keys) != 2 || keys[0][1] == keys[1][1] {
			t.Errorf("routing HTML for role %v lost distinct switches", role)
		}
	}
}

func TestRoutingClassifiesManagedTargetsThroughCompiledReserves(t *testing.T) {
	for _, tc := range []struct {
		name, node, reserve, chainFallback, label string
		class                                     stats.TargetClass
	}{
		{"VPN reserve", "auto", "reserve", "", "All traffic through VPN", stats.TargetVPN},
		{"missing pin with mixed reserve", strings.Repeat("a", 32), "reserve", model.TargetDirect, "All traffic through VPN", stats.TargetMixed},
		{"direct reserve", "auto", model.TargetDirect, "", "The main connection for the home network routes directly.", stats.TargetDirect},
		{"blocking without reserve", "auto", "", "", "The main connection blocks traffic.", stats.TargetBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := model.ManagedTarget("fixture", tc.node)
			cfg := &model.Config{
				Failover: model.Failover{URL: "http://127.0.0.1:1/probe"},
				Subscriptions: []subscription.Source{
					{ID: "fixture", URL: "https://127.0.0.1:1/catalog", Fallback: tc.reserve},
				},
				Connections: []model.Connection{
					{ID: "reserve", Type: model.ConnLink, Link: "socks5://127.0.0.1:1", Fallback: tc.chainFallback},
				},
				Networks: []model.Network{
					{Name: "Home", CIDR: "192.0.2.0/24", Mode: model.ModeSplit, Target: target, Default: model.TargetDirect},
				},
			}
			cfg.Defaults()
			saved, err := cfg.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			_, path := writeConfigFile(t, string(saved))
			d := startDaemon(t, path, cfg)
			deps := uiDeps{daemon: d}
			if subs := deps.Subscriptions(); len(subs) != 1 || len(subs[0].Nodes) != 0 {
				t.Fatal("the adapter fixture must start with an empty catalog")
			}
			if class := deps.OverviewStatus().Connections[target].Class; class != tc.class {
				t.Errorf("managed target class = %v, want %v", class, tc.class)
			}
			page := ui.New(deps, ui.Options{Role: func(*http.Request) ui.Role { return ui.RoleManage }})
			get := httptest.NewRecorder()
			page.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/routing", nil))
			if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), tc.label) {
				t.Errorf("routing page HTTP %d, missing reserve copy %q", get.Code, tc.label)
			}
			form := url.Values{"rev": {ui.Revision(d.Config())}, "mode": {"all"}}
			request := httptest.NewRequest(http.MethodPost, "/routing", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			page.ServeHTTP(response, request)
			wantCode, wantDefault := http.StatusUnprocessableEntity, model.TargetDirect
			if tc.class == stats.TargetVPN || tc.class == stats.TargetMixed {
				wantCode, wantDefault = http.StatusSeeOther, target
			}
			if response.Code != wantCode || d.Config().Networks[0].Default != wantDefault {
				t.Errorf("routing POST HTTP %d, want %d and default %q", response.Code, wantCode, wantDefault)
			}
		})
	}
}

type routingRoundTrip func(*http.Request) (*http.Response, error)

func (run routingRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return run(r) }

type routingSnapshotDaemon struct {
	managementDaemon
	rules compile.ProviderRules
	cfg   *model.Config
}

func (d routingSnapshotDaemon) ProviderRules() (compile.ProviderRules, *model.ProviderRulesSettings, daemon.ProviderRulesState) {
	return d.rules, &model.ProviderRulesSettings{Source: "fixture"}, daemon.ProviderRulesPartial
}

func (d routingSnapshotDaemon) Config() *model.Config { return d.cfg.Clone() }

func (d routingSnapshotDaemon) RoutingStatus() daemon.RoutingStatus {
	return daemon.RoutingStatus{
		Ready: true, TargetClasses: map[string]stats.TargetClass{d.cfg.Networks[0].Target: stats.TargetVPN},
	}
}

func (routingSnapshotDaemon) Subscriptions() []daemon.SubscriptionStatus { return nil }
