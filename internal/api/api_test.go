package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

type fakeDaemon struct {
	cfg      *model.Config
	applied  *model.Config
	failErr  error
	journals journal.Set
	limits   []int
}

func (f *fakeDaemon) Journal(k journal.Kind) *journal.Journal { return f.journals[k] }

func (f *fakeDaemon) Config() *model.Config { return f.cfg }
func (f *fakeDaemon) Apply(_ context.Context, c *model.Config) error {
	if f.failErr != nil {
		return f.failErr
	}
	if err := c.Validate(); err != nil {
		return err
	}
	f.applied, f.cfg = c, c
	return nil
}
func (f *fakeDaemon) Status(context.Context) daemon.Status { return daemon.Status{Mode: "redirect"} }
func (f *fakeDaemon) Devices() []daemon.Device {
	return []daemon.Device{{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.7.10"}}
}

func (f *fakeDaemon) Stats(bool) stats.Snapshot { return stats.Snapshot{} }
func (f *fakeDaemon) Hosts(_, _ string, limit int) ([]stats.Host, int) {
	f.limits = append(f.limits, limit)
	return []stats.Host{{Host: "youtube.com", Down: 10}}, 1
}

func newServer() (*Server, *fakeDaemon) {
	cfg := &model.Config{}
	cfg.Defaults()
	d := &fakeDaemon{cfg: cfg, journals: journal.NewSet("")}
	return &Server{D: d}, d
}

func do(t *testing.T, h http.Handler, method, path, body, token, remote string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = remote
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const lan = "192.168.7.88:5000"

const local = "127.0.0.1:5000"

func TestControlAPIAcceptsLoopbackWithoutToken(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	for _, remote := range []string{"127.0.0.1:5000", "[::1]:5000", "[::ffff:127.0.0.1]:5000"} {
		if c := do(t, h, "GET", "/api/status", "", "", remote).Code; c != http.StatusOK {
			t.Errorf("%s: %d", remote, c)
		}
	}
}

func TestControlAPIRejectsLANWithoutKeenetic(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	w := do(t, h, "GET", "/api/status", "", "", lan)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "local access only") {
		t.Errorf("LAN peer: %d %s", w.Code, w.Body)
	}
	// A forwarding header cannot turn a LAN peer into a loopback one.
	r := httptest.NewRequest("GET", "/api/status", nil)
	r.RemoteAddr = lan
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("X-Forwarded-For: %d", rec.Code)
	}
	if c := do(t, h, "GET", "/api/status", "", "", "8.8.8.8:1234").Code; c != http.StatusForbidden {
		t.Errorf("from the internet: %d", c)
	}
}

func TestControlAPIIgnoresBearerHeader(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	if c := do(t, h, "GET", "/api/status", "", "wrong", local).Code; c != http.StatusOK {
		t.Errorf("loopback with a stray token: %d", c)
	}
	if c := do(t, h, "GET", "/api/status", "", "secret", lan).Code; c != http.StatusForbidden {
		t.Errorf("a token does not open the API to a LAN peer: %d", c)
	}
}

func TestSessionReportsLoopbackAccess(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	for remote, want := range map[string]bool{local: true, lan: false} {
		var sess map[string]any
		w := do(t, h, "GET", "/api/session", "", "", remote)
		json.Unmarshal(w.Body.Bytes(), &sess)
		if w.Code != http.StatusOK || sess["authed"] != want {
			t.Errorf("session for %s: %d %v", remote, w.Code, sess)
		}
	}
	if c := do(t, h, "POST", "/api/login", `{"token":"x"}`, "", local).Code; c == http.StatusOK {
		t.Errorf("token login still exists: %d", c)
	}
}

func TestStatusIncludesRunningBuild(t *testing.T) {
	s, _ := newServer()
	w := do(t, s.Handler(), "GET", "/api/status", "", "secret", local)
	var got struct {
		Mode  string `json:"mode"`
		Build struct {
			Variant string `json:"variant"`
			Arch    string `json:"arch"`
		} `json:"build"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || got.Mode != "redirect" || got.Build.Arch != runtime.GOARCH ||
		(got.Build.Variant != "full" && got.Build.Variant != "lite") {
		t.Fatalf("status did not include the running build: %d %s", w.Code, w.Body)
	}
}

func TestPutConfig(t *testing.T) {
	s, d := newServer()
	h := s.Handler()
	body := `{"groups":[{"name":"g","target":"direct","entries":["example.com"]}]}`
	w := do(t, h, "PUT", "/api/config", body, "secret", local)
	if w.Code != http.StatusOK || d.applied == nil || d.applied.Groups[0].Entries[0] != "example.com" {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	bad := `{"groups":[{"name":"g","target":"nowhere","entries":["example.com"]}]}`
	w = do(t, h, "PUT", "/api/config", bad, "secret", local)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "nowhere") {
		t.Errorf("invalid configuration: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "PUT", "/api/config", `{"unknown":1}`, "secret", local)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", w.Code)
	}
	d.failErr = errors.New("sing-box rejected")
	w = do(t, h, "PUT", "/api/config", body, "secret", local)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "sing-box") {
		t.Errorf("apply error: %d %s", w.Code, w.Body)
	}
}

func TestParseLink(t *testing.T) {
	s, _ := newServer()
	w := do(t, s.Handler(), "POST", "/api/links/parse", "{\"link\":\"trojan://pw@tr.example.com:443#\u041c\u043e\u0439\"}", "secret", local)
	var got map[string]any
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 200 || got["protocol"] != "trojan" || got["name"] != "\u041c\u043e\u0439" || got["server"] != "tr.example.com" {
		t.Errorf("parse: %d %v", w.Code, got)
	}
	w = do(t, s.Handler(), "POST", "/api/links/parse", `{"link":"vless://u@h:1?type=xhttp"}`, "secret", local)
	json.Unmarshal(w.Body.Bytes(), &got)
	transport, _ := got["transport"].(map[string]any)
	if w.Code != 200 || got["type"] != "link" || got["protocol"] != "vless" || transport["type"] != "xhttp" {
		t.Errorf("xhttp preview: %d %v", w.Code, got)
	}
	w = do(t, s.Handler(), "POST", "/api/links/parse", `{"link":"vless://u@h:1?type=nope"}`, "secret", local)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid transport: %d %s", w.Code, w.Body)
	}
	w = do(t, s.Handler(), "POST", "/api/links/parse", `{"link":"`+ttPreviewLink()+`"}`, "secret", local)
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 200 || got["type"] != "link" || got["protocol"] != "trusttunnel" || got["name"] != "Finland" || got["server"] != "203.0.113.50" || got["tls"] != true {
		t.Errorf("tt preview: %d %v", w.Code, got)
	}
	if _, ok := got["password"]; ok {
		t.Errorf("preview exposed credentials: %v", got)
	}
}

func ttPreviewLink() string {
	var b []byte
	field := func(tag byte, v string) { b = append(append(b, tag, byte(len(v))), v...) }
	field(0x01, "vpn.example.com")
	field(0x02, "203.0.113.50:443")
	field(0x05, "user")
	field(0x06, "pass")
	field(0x0C, "Finland")
	return "tt://?" + base64.RawURLEncoding.EncodeToString(b)
}

func TestLegacyTrustTunnelMixIsRejected(t *testing.T) {
	s, d := newServer()
	body := `{"connections":[{"id":"tt","type":"trusttunnel","link":"tt://?one","trusttunnel":{"link":"tt://?two","binary":"/opt/bin/trusttunnel_client"}}]}`
	w := do(t, s.Handler(), "PUT", "/api/config", body, "secret", local)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "conflicts") {
		t.Fatalf("raw API: %d %s", w.Code, w.Body)
	}
	if d.applied != nil {
		t.Fatal("mixed payload was applied")
	}
}

func TestStatsEndpoints(t *testing.T) {
	s, _ := newServer()
	if w := do(t, s.Handler(), "GET", "/api/stats?series=1", "", "secret", local); w.Code != 200 || !strings.Contains(w.Body.String(), "outbounds") {
		t.Errorf("stats: %d %s", w.Code, w.Body)
	}
	if w := do(t, s.Handler(), "GET", "/api/stats/hosts?tag=fi", "", "secret", local); w.Code != 200 || !strings.Contains(w.Body.String(), "youtube.com") {
		t.Errorf("hosts: %d %s", w.Code, w.Body)
	}
}

// The panel requests a short preview, then every retained host; invalid limits keep the old default.
func TestHostsLimit(t *testing.T) {
	s, d := newServer()
	for _, l := range []string{"10", strconv.Itoa(stats.MaxHosts), strconv.Itoa(stats.MaxHosts + 1), "0", "x"} {
		if w := do(t, s.Handler(), "GET", "/api/stats/hosts?tag=fi&limit="+l, "", "secret", local); w.Code != 200 {
			t.Fatalf("limit %s: %d", l, w.Code)
		}
	}
	want := []int{10, stats.MaxHosts, 200, 200, 200}
	if !slices.Equal(d.limits, want) {
		t.Errorf("limits %v, want %v", d.limits, want)
	}
}

func TestJournalEndpoints(t *testing.T) {
	s, d := newServer()
	h := s.Handler()
	d.journals[journal.Audit].Add(journal.Entry{Actor: "user", Action: "Configuration rejected", Target: "config", Result: "error", Details: "invalid, 192.168.7.88"})
	d.journals[journal.Audit].Add(journal.Entry{Actor: "user", Action: "Configuration applied", Target: "config", Result: "ok"})
	d.journals[journal.System].Add(journal.Entry{Level: "WARN", Source: "keenproxy", Message: "entry appeared in message"})

	w := do(t, h, "GET", "/api/journal/audit?result=error", "", "secret", local)
	var page journal.Page
	json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != http.StatusOK || len(page.Entries) != 1 || !strings.Contains(page.Entries[0].Details, "192.168.7.88") {
		t.Errorf("audit filter: %d %s", w.Code, w.Body)
	}
	if !slices.Contains(page.Facets["result"], "ok") {
		t.Errorf("filter values: %v", page.Facets)
	}
	if c := do(t, h, "GET", "/api/journal/nope", "", "secret", local).Code; c != http.StatusNotFound {
		t.Errorf("unknown journal: %d", c)
	}
}

func TestRootIsPlaceholderUntilUIExists(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	w := do(t, h, "GET", "/", "", "", "127.0.0.1:1234")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "KeenProxy interface is being rebuilt") {
		t.Fatalf("root = %d %q", w.Code, w.Body.String())
	}
	if w := do(t, h, "GET", "/api/unknown", "", "", "127.0.0.1:1234"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown api path = %d", w.Code)
	}
}

func TestRemovedEndpointsAreNotFound(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	for _, path := range []string{"/api/geoip", "/api/domains", "/api/config/yaml", "/api/catalog", "/api/journal/routes/stream", "/api/journal/routes/export"} {
		if w := do(t, h, "GET", path, "", "", local); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, w.Code)
		}
	}
	if w := do(t, h, "GET", "/api/journal/routes", "", "", local); w.Code != http.StatusOK {
		t.Errorf("GET /api/journal/routes = %d, want 200", w.Code)
	}
}

func TestDNSBypassSourcesApply(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	const resolver = "192.168.37.53"
	applied := do(t, h, "PUT", "/api/config", `{"dns":{"bypass_sources":["`+resolver+`"]}}`, "", local)
	if applied.Code != http.StatusOK || !strings.Contains(applied.Body.String(), `"bypass_sources":["`+resolver+`"]`) {
		t.Fatalf("apply: %d %s", applied.Code, applied.Body)
	}
	bad := do(t, h, "PUT", "/api/config", `{"dns":{"bypass_sources":["192.168.37.0/24"]}}`, "", local)
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), "dns.bypass_sources[0]") {
		t.Fatalf("invalid apply: %d %s", bad.Code, bad.Body)
	}
}
