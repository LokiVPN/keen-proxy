package ui

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestConnectionDetailReveal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		role  Role
		query string
		shows bool
	}{
		{"masked", RoleManage, "", false},
		{"reveal", RoleManage, "?reveal=1", true},
		{"view", RoleView, "?reveal=1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDetailFixture(t)
			f.cfg.Connections[1].WireGuard.PrivateKey = "detail-synthetic-private<&>"
			f.cfg.Connections[1].WireGuard.Peer.PresharedKey = "detail-synthetic-preshared"
			f.cfg.Connections[1].Name = "Cabin <script>"
			h := New(f, setupTestOptions(tc.role))
			w := setupRequest(h, "/connections/id/backup"+tc.query, nil)
			requireDetailStatus(t, w, http.StatusOK)
			assertPageHeaders(t, w.Result(), "en")
			body := w.Body.String()
			assertContains(t, body, "Cabin &lt;script&gt;", "WireGuard", "example.test:51820", "198.51.100.2/32")
			for _, secret := range []string{"detail-synthetic-private&lt;&amp;&gt;", "detail-synthetic-preshared", "synthetic-key"} {
				if strings.Contains(body, secret) != tc.shows {
					t.Errorf("credential visibility differs from the role and request")
				}
			}
			if strings.Contains(body, "<script>") || strings.Contains(body, "style=") {
				t.Fatal("rendered raw markup or inline CSS")
			}
			if tc.role == RoleView {
				if strings.Contains(body, "?reveal=") || strings.Contains(body, "/replace") {
					t.Fatal("viewer received a reveal or replace link")
				}
				for _, path := range []string{"/connections/id/backup", "/connections/id/backup/probe", "/connections/id/backup/delete"} {
					requireDetailStatus(t, setupRequest(h, path, detailForm(f)), http.StatusForbidden)
				}
				if f.applies != 0 || len(f.probes) != 0 {
					t.Fatal("a viewer action reached the configuration or probe")
				}
			} else {
				assertContains(t, body, `href="/connections/id/backup/replace"`)
			}
		})
	}
}

func TestConnectionDetailMasksWireGuardKeyWithUnusedPadBits(t *testing.T) {
	const keyBytes = "padbits-test-private-key-bytes01"
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	encoded := []byte(base64.StdEncoding.EncodeToString([]byte(keyBytes)))
	last := len(encoded) - 2 // The final data character has two unused bits.
	encoded[last] = alphabet[strings.IndexByte(alphabet, encoded[last])+1]
	privateKey := string(encoded)
	if decoded, err := base64.StdEncoding.DecodeString(privateKey); err != nil || string(decoded) != keyBytes {
		t.Fatal("fixture does not decode to the same bytes as the core expects")
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(privateKey); err == nil {
		t.Fatal("fixture has canonical padding bits")
	}

	f := newDetailFixture(t)
	wg := f.cfg.Connections[1].WireGuard
	wg.PrivateKey = privateKey
	wg.Peer.PublicKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32)))
	wg.Peer.Endpoint = keyBytes + ".example.test:51820"
	for _, tc := range []struct {
		role  Role
		query string
	}{
		{RoleManage, ""},
		{RoleView, "?reveal=1"},
	} {
		w := setupRequest(New(f, setupTestOptions(tc.role)), "/connections/id/backup"+tc.query, nil)
		requireDetailStatus(t, w, http.StatusOK)
		body := w.Body.String()
		if strings.Contains(body, keyBytes) || strings.Contains(body, privateKey) || !strings.Contains(body, `title="Hidden">Hidden</dd>`) {
			t.Errorf("masked server fact or endpoint revealed key bytes for role %v", tc.role)
		}
	}
}

func TestConnectionDetailFactsKeepOpaqueParametersPrivate(t *testing.T) {
	f := newDetailFixture(t)
	f.cfg.Connections[0] = model.Connection{
		ID: "old", Name: "Office", Type: model.ConnSingBox,
		Outbound: map[string]any{
			"type": "trojan", "server": "server.example", "server_port": 443, "password": "synthetic-pw",
			"tls":       map[string]any{"enabled": true, "server_name": "sni.example"},
			"transport": map[string]any{"type": "ws", "headers": map[string]any{"Host": "ws.example", "Cookie": "session=opaque-test-value"}},
		},
	}
	f.health.Class = stats.TargetMixed
	h := New(f, setupTestOptions(RoleManage))
	w := setupRequest(h, "/connections/id/old", nil)
	requireDetailStatus(t, w, http.StatusOK)
	body := w.Body.String()
	assertContains(t, body, "Trojan", "server.example:443", "sni.example", "WebSocket", "Follows this connection")
	if strings.Contains(body, "synthetic-pw") || strings.Contains(body, "opaque-test-value") {
		t.Fatal("default detail exposed opaque parameters")
	}
	w = setupRequest(h, "/connections/id/old?reveal=1", nil)
	requireDetailStatus(t, w, http.StatusOK)
	assertContains(t, w.Body.String(), "synthetic-pw", "opaque-test-value")
	f.cfg.Connections[0].Outbound["server"] = "opaque-test-value.example"
	f.cfg.Connections[0].Outbound["tls"].(map[string]any)["server_name"] = "synthetic-pw.example"
	w = setupRequest(New(f, setupTestOptions(RoleView)), "/connections/id/old?reveal=1", nil)
	requireDetailStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), "synthetic-pw") || strings.Contains(w.Body.String(), "opaque-test-value") {
		t.Fatal("viewer facts repeat a credential from the stored payload")
	}
}

func TestConnectionDetailMasksDecodedCredentials(t *testing.T) {
	const secret = "display-secret-fixture"
	var byteArray []any
	for _, b := range []byte(secret) {
		byteArray = append(byteArray, float64(b))
	}
	for _, tc := range []struct {
		name, kind string
		options    map[string]any
	}{
		{"hysteria", "hysteria", map[string]any{"AUTH": base64.StdEncoding.EncodeToString([]byte(secret))}},
		{"hysteria byte array", "hysteria", map[string]any{"AUTH": byteArray}},
		{"basic header", "http", map[string]any{"headers": map[string]any{
			"authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture-user:"+secret)),
		}}},
		{"legacy Basic bytes", "http", map[string]any{"headers": map[string]any{
			"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("\xe9:"+secret)),
		}}},
		{"duplicate display values", "trojan", nil},
		{"public-looking field", "trojan", map[string]any{"transport": map[string]any{"type": "ws", "headers": map[string]any{
			"Host": secret + ".example", "X-Name": base64.RawURLEncoding.EncodeToString([]byte(secret)),
		}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDetailFixture(t)
			profile := tc.options
			sni := secret + ".sni.example"
			if profile == nil {
				profile = make(map[string]any)
				sni = secret + ".example"
			}
			profile["type"], profile["server"], profile["server_port"] = tc.kind, secret+".example", 443
			profile["tls"] = map[string]any{"enabled": true, "server_name": sni}
			f.cfg.Connections[0] = model.Connection{ID: "old", Name: "Office", Type: model.ConnSingBox, Outbound: profile}
			for _, role := range []Role{RoleManage, RoleView} {
				h := New(f, setupTestOptions(role))
				w := setupRequest(h, "/connections/id/old", nil)
				requireDetailStatus(t, w, http.StatusOK)
				body := w.Body.String()
				if strings.Contains(body, secret) || strings.Count(body, ">Hidden</dd>") != 2 {
					t.Errorf("masked facts exposed or omitted a decoded credential for role %v", role)
				}
			}
		})
	}
}

func TestConnectionDetailSelectorListsBuiltInMembers(t *testing.T) {
	f := newDetailFixture(t)
	f.cfg.Connections[1] = model.Connection{ID: "backup", Name: "Selector", Type: model.ConnSingBox,
		Outbound: map[string]any{"type": "selector", "outbounds": []string{"old", model.TargetDirect, model.TargetBlock}}}
	f.health.TrafficGroup, f.health.TrafficMembers = true, []string{"old", model.TargetDirect, model.TargetBlock}
	h := New(f, setupTestOptions(RoleView))
	for _, path := range []string{"/connections/id/backup", "/fragments/connection/backup/speed", "/fragments/connection/backup/hosts"} {
		w := setupRequest(h, path, nil)
		requireDetailStatus(t, w, http.StatusOK)
		body := w.Body.String()
		for _, want := range []string{`href="/connections/id/old"`, "<li>Direct</li>", "<li>Block</li>",
			"Traffic through built-in members is not attributed to a connection page."} {
			if !strings.Contains(body, want) {
				t.Errorf("%s omitted %q", path, want)
			}
		}
		if strings.Contains(body, `href="/connections/id/direct"`) || strings.Contains(body, `href="/connections/id/block"`) {
			t.Error("built-in member unnecessarily links to a missing page")
		}
	}
}

func TestConnectionDetailProbeKeepsStagedSettings(t *testing.T) {
	f := newDetailFixture(t)
	h := New(f, setupTestOptions(RoleManage))
	path := "/connections/id/backup"
	staged := detailForm(f)
	staged.Set("fallback", "disabled")
	w := setupRequest(h, path+"/probe", staged)
	requireDetailStatus(t, w, http.StatusOK)
	body := w.Body.String()
	input := connectionControl(t, body, "input", "enabled", "1")
	_, checked := input["checked"]
	if checked || !strings.Contains(body, `<option value="disabled" selected>`) || !strings.Contains(body, "data-dirty") {
		t.Fatal("probe discarded the staged switch or reserve")
	}
	assertContains(t, body, "82 ms")
	if f.applies != 0 || f.cfg.Connections[1].Disabled || f.cfg.Connections[1].Fallback != model.TargetDirect ||
		!slices.Equal(f.probes, []string{"backup"}) {
		t.Fatal("probe applied draft settings or probed a different profile")
	}
	f.probeErr = errors.New("synthetic private probe error")
	w = setupRequest(h, path+"/probe", staged)
	requireDetailStatus(t, w, http.StatusServiceUnavailable)
	body = w.Body.String()
	if !strings.Contains(body, `<option value="disabled" selected>`) || strings.Contains(body, f.probeErr.Error()) {
		t.Fatal("probe error discarded the draft or exposed raw error text")
	}
}

func TestConnectionDetailFallbackAndSave(t *testing.T) {
	f := newDetailFixture(t)
	f.cfg.Connections = append(f.cfg.Connections, model.Connection{
		ID: "via-old", Name: "Another office", Type: model.ConnLink, Link: "socks5://example.test:1080", Fallback: "old",
	})
	f.cfg.Paused = true
	h := New(f, setupTestOptions(RoleManage))
	path := "/connections/id/backup"
	w := setupRequest(h, path, nil)
	requireDetailStatus(t, w, http.StatusOK)
	options := connectionOptionsFromPage(t, w.Body.String(), "fallback")
	if want := []string{"", "direct", "disabled"}; !slices.Equal(options, want) {
		t.Fatalf("fallback options = %q, want %q", options, want)
	}
	for _, target := range options {
		cfg := f.Config()
		cfg.Connections[1].Fallback = target
		if err := cfg.Validate(); err != nil {
			t.Errorf("offered fallback %q rejected by the model: %v", target, err)
		}
	}
	for _, target := range []string{"backup", "old", "via-old", "block", "missing"} {
		form := detailForm(f)
		form.Set("fallback", target)
		w = setupRequest(h, path, form)
		requireDetailStatus(t, w, http.StatusUnprocessableEntity)
		if f.applies != 0 {
			t.Fatalf("invalid fallback %q reached Apply", target)
		}
	}
	want := f.Config()
	want.Connections[1].Disabled = true
	want.Connections[1].Fallback = "disabled"
	f.cfg.Connections[2].Fallback = model.TargetDirect
	want.Connections[2].Fallback = model.TargetDirect
	form := detailForm(f)
	form.Set("fallback", "disabled")
	w = setupRequest(h, path, form)
	requireDetailStatus(t, w, http.StatusSeeOther)
	if w.Header().Get("Location") != path || f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
		t.Fatal("save did not preserve unrelated configuration or redirect to the detail")
	}
	w = setupRequest(h, path, nil)
	_, chain, _ := strings.Cut(w.Body.String(), `aria-label="Reserve chain">`)
	chain, _, _ = strings.Cut(chain, "</ol>")
	assertContains(t, chain, "Cabin", "Office SOCKS", "Disabled", "Direct")
	switchInput := connectionControl(t, w.Body.String(), "input", "enabled", "1")
	if _, checked := switchInput["checked"]; checked {
		t.Fatal("the enable switch does not reflect the saved disabled flag")
	}
	w = setupRequest(h, path, form)
	requireDetailStatus(t, w, http.StatusConflict)
	if f.applies != 1 {
		t.Fatal("stale edits reached Apply")
	}
}

func TestConnectionDetailFallbackRespectsInheritedDNSConstraints(t *testing.T) {
	f := newDetailFixture(t)
	f.cfg.DNS.Route, f.cfg.DNS.Connection, f.cfg.DNS.Failure = "connection", "old", "strict"
	f.cfg.DNS.Upstreams = []string{"https://192.0.2.53/dns-query"}
	f.cfg.Connections[1].Fallback = ""
	f.cfg.Connections = append(f.cfg.Connections,
		model.Connection{ID: "raw-direct", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
		model.Connection{ID: "via-direct", Type: model.ConnLink, Link: "socks5://example.test:1080", Fallback: model.TargetDirect},
		model.Connection{ID: "via-raw", Type: model.ConnLink, Link: "socks5://example.test:1080", Fallback: "raw-direct"},
	)
	if err := f.Config().Validate(); err != nil {
		t.Fatalf("invalid DNS fixture: %v", err)
	}
	h := New(f, setupTestOptions(RoleManage))
	path := "/connections/id/backup"
	w := setupRequest(h, path, nil)
	requireDetailStatus(t, w, http.StatusOK)
	if got := connectionOptionsFromPage(t, w.Body.String(), "fallback"); !slices.Equal(got, []string{"", "disabled"}) {
		t.Fatalf("strict DNS reserve options = %q", got)
	}
	for _, target := range []string{"direct", "via-direct", "raw-direct", "via-raw"} {
		form := detailForm(f)
		form.Set("fallback", target)
		requireDetailStatus(t, setupRequest(h, path, form), http.StatusUnprocessableEntity)
	}
	if f.applies != 0 {
		t.Fatal("a forbidden DNS reserve reached Apply")
	}
	f.cfg.DNS.Failure = "direct"
	w = setupRequest(h, path, nil)
	requireDetailStatus(t, w, http.StatusOK)
	if got := connectionOptionsFromPage(t, w.Body.String(), "fallback"); !slices.Equal(got, []string{"", "direct", "disabled", "via-direct"}) {
		t.Fatalf("direct-failure DNS reserve options = %q", got)
	}
}

func TestConnectionDetailDeletionListsEveryReference(t *testing.T) {
	f := newDetailFixture(t)
	f.cfg.Networks[0].Target = "backup"
	f.cfg.Networks[0].Default = "backup"
	f.cfg.Networks[1].Target = "backup"
	f.cfg.Groups[0].Target = "backup"
	f.cfg.Groups[2].Target = "backup"
	f.cfg.Clients[0].Target, f.cfg.Clients[0].Name = "backup", "Test device"
	f.cfg.DNS.Route, f.cfg.DNS.Connection = "connection", "backup"
	f.cfg.Subscriptions = append(f.cfg.Subscriptions, subscription.Source{ID: "another-source", URL: "https://second.example/config", Fallback: "backup"})
	f.profileRefs = []string{"disabled"}
	h := New(f, setupTestOptions(RoleManage))
	path := "/connections/id/backup/delete"
	w := setupRequest(h, path, url.Values{"rev": {Revision(f.Config())}})
	requireDetailStatus(t, w, http.StatusConflict)
	assertContains(t, w.Body.String(), "Main connection", "Default route for Home", "Network Other", "own-vpn", "additional",
		"Reserve for Office", "Reserve for subscription sample", "Reserve for subscription another-source", "Test device", "DNS connection", "Sing-box profile Office SOCKS")
	if f.applies != 0 || !slices.ContainsFunc(f.Config().Connections, func(c model.Connection) bool { return c.ID == "backup" }) {
		t.Fatal("delete touched applied config despite references")
	}

	// Remove only the references to the connection and post a current revision.
	f.cfg.Networks[0].Target, f.cfg.Networks[0].Default = "old", "old"
	f.cfg.Networks[1].Target = "old"
	f.cfg.Groups[0].Target, f.cfg.Groups[2].Target = "old", "old"
	f.cfg.Clients[0].Target = "old"
	f.cfg.DNS.Connection = "old"
	f.cfg.Subscriptions[0].Fallback, f.cfg.Subscriptions[1].Fallback = "old", "old"
	f.cfg.Connections[0].Fallback = ""
	f.profileRefs = nil
	want := f.Config()
	want.Connections = slices.Delete(want.Connections, 1, 2)
	form := url.Values{"rev": {Revision(f.Config())}}
	w = setupRequest(h, path, form)
	requireDetailStatus(t, w, http.StatusSeeOther)
	if w.Header().Get("Location") != "/connections" || f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
		t.Fatal("delete did not remove only the selected connection")
	}
	w = setupRequest(h, "/connections/id/backup", nil)
	requireDetailStatus(t, w, http.StatusNotFound)
}

func TestConnectionDetailProbeAndFragmentsWithLegacyIDs(t *testing.T) {
	for _, tc := range []struct{ id, segment string }{
		{"new", "new"}, {"..", "~.."}, {"~leading", "~~leading"}, {"office/socks", "office%2Fsocks"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := newDetailFixture(t)
			f.cfg.Connections[1].ID = tc.id
			f.cfg.Connections[0].Fallback, f.cfg.Subscriptions[0].Fallback = tc.id, tc.id
			f.hosts = []stats.Host{{Host: "<example.test>", Down: 1024, Up: 2}}
			f.hostTotal = 9
			f.series = []stats.Point{
				{T: time.Now().Add(-time.Minute).UnixMilli(), Down: 5e6},
				{T: time.Now().Add(-time.Second).UnixMilli(), Down: 4.2e6, Up: 0.6e6},
			}
			h := New(f, setupTestOptions(RoleManage))
			path := "/connections/id/" + tc.segment
			fragment := "/fragments/connection/" + tc.segment
			w := setupRequest(h, path, nil)
			requireDetailStatus(t, w, http.StatusOK)
			assertContains(t, w.Body.String(), `formaction="`+path+`/probe"`, `action="`+path+`/delete"`,
				`href="`+path+`/replace"`, `data-fragment="`+fragment+`/health"`, `data-fragment="`+fragment+`/speed"`,
				`data-fragment="`+fragment+`/hosts"`)
			for _, part := range []string{"/health", "/speed", "/hosts"} {
				w = setupRequest(New(f, setupTestOptions(RoleView)), fragment+part, nil)
				requireDetailStatus(t, w, http.StatusOK)
				assertPageHeaders(t, w.Result(), "en")
				if strings.Contains(w.Body.String(), "<!doctype") || strings.Contains(w.Body.String(), "synthetic-token") {
					t.Fatal("fragment returned a full document or a credential")
				}
				switch part {
				case "/speed":
					assertContains(t, w.Body.String(), "Incoming 4.2 Mbit/s", "Outgoing 0.6 Mbit/s", `<path class="rx-l"`)
				case "/hosts":
					assertContains(t, w.Body.String(), "&lt;example.test&gt;", "1 KB", "2 B", "Show all (9)")
				}
			}
			if len(f.probes) != 0 {
				t.Fatal("a GET started a probe")
			}
			w = setupRequest(h, path+"/probe", url.Values{"rev": {"stale"}})
			requireDetailStatus(t, w, http.StatusConflict)
			if len(f.probes) != 0 {
				t.Fatal("a stale action started a probe")
			}
			form := detailForm(f)
			form.Add("enabled", "1")
			w = setupRequest(h, path+"/probe", form)
			requireDetailStatus(t, w, http.StatusOK)
			assertContains(t, w.Body.String(), "Connection checked")
			if !slices.Equal(f.probes, []string{tc.id}) || f.applies != 0 {
				t.Fatalf("probes = %v, apply calls = %d", f.probes, f.applies)
			}
			w = setupRequest(h, fragment+"/health", nil)
			assertContains(t, w.Body.String(), "82 ms")
		})
	}
}

func detailForm(f *detailFixture) url.Values {
	return url.Values{"rev": {Revision(f.Config())}, "enabled": {"0"}, "fallback": {model.TargetDirect}}
}

func requireDetailStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("connection detail returned HTTP %d, want %d", w.Code, want)
	}
}

type detailFixture struct {
	*connectionsFixture
	health      ConnectionHealth
	series      []stats.Point
	hosts       []stats.Host
	hostTotal   int
	probes      []string
	probeErr    error
	profileRefs []string
}

func newDetailFixture(t *testing.T) *detailFixture {
	return &detailFixture{connectionsFixture: newConnectionsFixture(t)}
}

func (*detailFixture) ConnectionReserveTargets(_ context.Context, cfg *model.Config, id string) []string {
	return cfg.ConnectionFallbackTargets(id)
}

func (*detailFixture) CheckConnectionSettings(_ context.Context, cfg *model.Config) error {
	return cfg.Validate()
}

func (*detailFixture) ValidateConnectionSettings(_ context.Context, cfg *model.Config) error {
	return cfg.Validate()
}

func (f *detailFixture) ConnectionHealth(id string) (ConnectionHealth, bool) {
	i := connectionIndex(f.cfg, id)
	health := f.health
	if i >= 0 {
		health.Disabled = f.cfg.Connections[i].Disabled
	}
	return health, i >= 0
}

func (*detailFixture) ConnectionGroupMembers(context.Context, model.Connection) []string { return nil }

func (f *detailFixture) ConnectionTraffic(string) (int, []stats.Point) { return 14, f.series }

func (f *detailFixture) ConnectionHosts(string, int) ([]stats.Host, int) { return f.hosts, f.hostTotal }

func (f *detailFixture) ConnectionProfileReferences(context.Context, *model.Config, string) ([]string, error) {
	return f.profileRefs, nil
}

func (f *detailFixture) CheckConnection(_ context.Context, id, rev string) error {
	if Revision(f.Config()) != rev {
		return model.ErrConfigChanged
	}
	i := connectionIndex(f.Config(), id)
	if i < 0 || f.Config().Connections[i].Disabled {
		return errors.New("fixture connection is unavailable")
	}
	if f.probeErr != nil {
		return f.probeErr
	}
	f.probes = append(f.probes, id)
	f.health.Checked, f.health.Available, f.health.LatencyMS = time.Now(), true, 82
	return nil
}
