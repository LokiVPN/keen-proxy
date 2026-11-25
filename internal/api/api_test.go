package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
func (f *fakeDaemon) Stats(bool) stats.Snapshot            { return stats.Snapshot{} }
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
	r.Host = "127.0.0.1:8086"
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
	if c := do(t, h, "POST", "/api/login", `{"token":"x"}`, "", local).Code; c != http.StatusNotFound {
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
	d.failErr = &model.AppliedUnsavedError{Err: errors.New("read-only config file")}
	w = do(t, h, "PUT", "/api/config", body, "secret", local)
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusUnprocessableEntity ||
		got["error"] != "configuration applied but not saved: read-only config file" {
		t.Errorf("applied-but-unsaved API response: %d %s", w.Code, w.Body)
	}
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

// Loopback callers may request every retained host; invalid limits use the default.
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

func TestPagesHandlerReceivesOnlyPagePaths(t *testing.T) {
	s, _ := newServer()
	s.Pages = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path)
	})
	h := s.Handler()
	for _, path := range []string{"/", "/connections"} {
		if w := do(t, h, "GET", path, "", "", local); w.Code != http.StatusOK || w.Body.String() != path {
			t.Errorf("GET %s: HTTP %d, body %q", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/unknown", "/api%2Funknown"} {
		if w := do(t, h, "GET", path, "", "", local); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, w.Code)
		}
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

func TestPageReplacedEndpointsReturnJSONNotFound(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	for _, target := range []string{
		"POST /api/diagnostics/check",
		"GET /api/diagnostics/bundle",
		"GET /api/subscriptions/status",
		"POST /api/subscriptions/preview",
		"POST /api/subscriptions/sample/refresh",
		"POST /api/subscriptions/sample/check",
		"POST /api/config/validate",
		"GET /api/devices",
		"POST /api/links/parse",
		"POST /api/amnezia/import",
		"GET /api/updates",
		"POST /api/updates/check",
		"PUT /api/updates/preferences",
		"POST /api/updates/install",
	} {
		method, path := routeMethod(target)
		w := do(t, h, method, path, "{}", "", local)
		if w.Code != http.StatusNotFound || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: HTTP %d, Content-Type %q, want JSON 404", target, w.Code, w.Header().Get("Content-Type"))
		}
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

func TestLoopbackRequiresLoopbackHost(t *testing.T) {
	s, _ := newServer()
	getPath := func(srv *Server, path, remote, host string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr, r.Host = remote, host
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w.Code
	}
	get := func(srv *Server, remote, host string) int { return getPath(srv, "/api/status", remote, host) }
	for _, tc := range []struct{ remote, host string }{
		{"127.0.0.1:5000", "127.0.0.1:8086"},
		{"127.0.0.1:5000", "localhost:8086"},
		{"127.0.0.1:5000", "LOCALHOST"},
		{"[::1]:5000", "[::1]:8086"},
	} {
		if c := get(s, tc.remote, tc.host); c != http.StatusOK {
			t.Errorf("%s with Host %s: %d, want 200", tc.remote, tc.host, c)
		}
	}
	for _, host := range []string{"name.keenetic.pro", "192.168.1.1:8086", "localhost.evil.example", ""} {
		if c := get(s, "127.0.0.1:5000", host); c != http.StatusForbidden {
			t.Errorf("Host %q without KeeneticOS: %d, want 403", host, c)
		}
	}
	k, _, _ := keeneticFixtureTags(t, []string{"http", "cli"})
	if c := get(k, "127.0.0.1:5000", "name.keenetic.pro"); c != http.StatusForbidden {
		t.Errorf("foreign Host with KeeneticOS: %d, want 403 (a LAN peer never reaches /api)", c)
	}
	if c := get(k, "127.0.0.1:5000", "127.0.0.1:8086"); c != http.StatusOK {
		t.Errorf("loopback Host with KeeneticOS: %d, want 200", c)
	}
	// A proxied request to a page goes through sign-in like any LAN peer.
	if c := getPath(k, "/", "127.0.0.1:5000", "name.keenetic.pro"); c != http.StatusForbidden {
		t.Errorf("proxied page with a foreign Host: %d, want 403", c)
	}
	if c := getPath(k, "/", "127.0.0.1:5000", "192.168.7.1:8086"); c != http.StatusUnauthorized {
		t.Errorf("proxied page with the panel Host and no session: %d, want 401", c)
	}
}

func TestSessionReportsLoopbackAccessInKeeneticMode(t *testing.T) {
	k, _, _ := keeneticFixtureTags(t, []string{"http", "cli"})
	r := httptest.NewRequest("GET", "/api/session", nil)
	r.RemoteAddr, r.Host = local, "127.0.0.1:8086"
	w := httptest.NewRecorder()
	k.Handler().ServeHTTP(w, r)
	var sess map[string]any
	json.Unmarshal(w.Body.Bytes(), &sess)
	if sess["authed"] != true {
		t.Fatalf("loopback session in KeeneticOS mode: %v", sess)
	}
}

// routeMethod splits a registered pattern into its method and path; the
// catch-alls have no method.
func routeMethod(pattern string) (method, path string) {
	if method, path, ok := strings.Cut(pattern, " "); ok {
		return method, path
	}
	return "", pattern
}

// routePaths exercises every journal kind and a child path for any catch-all.
func routePaths(pattern string) []string {
	_, path := routeMethod(pattern)
	switch {
	case strings.Contains(path, "{kind}"):
		var out []string
		for _, kind := range journal.Kinds {
			out = append(out, strings.Replace(path, "{kind}", string(kind), 1))
		}
		return out
	case strings.HasSuffix(path, "/"):
		return []string{path, path + "nothing-here"}
	}
	return []string{path}
}

// lanRequest is a browser request from a LAN peer to the panel address.
// Writes carry the same-origin Origin header a browser sends.
func lanRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	r.RemoteAddr, r.Host = lan, "192.168.7.1:8086"
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		r.Header.Set("Origin", "http://192.168.7.1:8086")
	}
	return r
}

// A LAN peer without a session gets an exact refusal on every path: each
// registered API route with its own method, HEAD and OPTIONS and unregistered
// API and page paths. Only the public routes answer, with their own method.
func TestEveryRouteRejectsLANPeers(t *testing.T) {
	plain, _ := newServer()
	keenetic, _, _ := keeneticFixtureTags(t, []string{"http", "cli"})
	unavailable, _ := newServer()
	unavailable.Unavailable = true
	type request struct {
		method, path string
		public       bool
	}
	var requests []request
	seen := map[string]bool{}
	wantPublic := map[string]bool{"GET /api/session": true, "POST /api/logout": true}
	for _, rt := range plain.routes() {
		seen[rt.pattern] = true
		method, _ := routeMethod(rt.pattern)
		methods := []string{method}
		if method == "" {
			methods = []string{http.MethodGet, http.MethodPost}
		}
		for _, path := range routePaths(rt.pattern) {
			for _, m := range append(methods, http.MethodHead, http.MethodOptions) {
				requests = append(requests, request{m, path, m == method && wantPublic[rt.pattern]})
			}
		}
	}
	for _, path := range []string{"/", "/connections", "/api/", "/api/nothing-here", "/api", "/api%2Fsession", "/api%2Flogout"} {
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodHead, http.MethodOptions} {
			requests = append(requests, request{m, path, false})
		}
	}
	type refusal struct {
		status int
		reason string
	}
	for _, mode := range []struct {
		name      string
		srv       *Server
		api, page refusal
	}{
		{"sign-in off", plain, refusal{http.StatusForbidden, "local access only"}, refusal{http.StatusForbidden, "local access only"}},
		{"keeneticos", keenetic, refusal{http.StatusForbidden, "local access only"}, refusal{http.StatusUnauthorized, "KeeneticOS sign-in required"}},
		{"unavailable", unavailable, refusal{http.StatusServiceUnavailable, "use an SSH tunnel"}, refusal{http.StatusServiceUnavailable, "use an SSH tunnel"}},
	} {
		for _, rq := range requests {
			w := serve(mode.srv, lanRequest(rq.method, rq.path))
			if rq.public {
				if w.Code != http.StatusOK {
					t.Errorf("%s: public %s %s from LAN: %d %q", mode.name, rq.method, rq.path, w.Code, w.Body)
				}
				continue
			}
			want, format := mode.page, "text/plain"
			// Refusals classify by the decoded path, so an encoded API path is JSON too.
			if decoded, _ := url.PathUnescape(rq.path); decoded == "/api" || strings.HasPrefix(decoded, "/api/") {
				want, format = mode.api, "application/json"
			}
			if w.Code != want.status || (rq.method != http.MethodHead && !strings.Contains(w.Body.String(), want.reason)) {
				t.Errorf("%s: %s %s from LAN: %d %q, want %d %q", mode.name, rq.method, rq.path, w.Code, w.Body, want.status, want.reason)
			}
			if !strings.HasPrefix(w.Header().Get("Content-Type"), format) || w.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s: %s %s from LAN: Content-Type %q, Cache-Control %q, want %s and no-store",
					mode.name, rq.method, rq.path, w.Header().Get("Content-Type"), w.Header().Get("Cache-Control"), format)
			}
		}
	}
	for p := range wantPublic {
		if !seen[p] {
			t.Errorf("public pattern %q is not a registered route", p)
		}
	}
}

// Pages and refusals pass through the injected UI boundary only after the
// central policy has decided the caller's access.
func TestPagesFollowTheKeeneticSession(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tags        []string
		method      string
		session     bool
		host        string
		unavailable bool
		want        int
		role        Role
	}{
		{"no session", []string{"http", "cli"}, "GET", false, "", false, http.StatusUnauthorized, RoleDeny},
		{"manage reads", []string{"http", "cli"}, "GET", true, "", false, http.StatusOK, RoleManage},
		{"manage writes", []string{"http", "cli"}, "POST", true, "", false, http.StatusOK, RoleManage},
		{"view reads", []string{"http", "readonly"}, "GET", true, "", false, http.StatusOK, RoleView},
		{"view reads headers", []string{"http", "readonly"}, "HEAD", true, "", false, http.StatusOK, RoleView},
		{"view cannot write", []string{"http", "readonly"}, "POST", true, "", false, http.StatusForbidden, RoleDeny},
		{"foreign host", []string{"http", "cli"}, "GET", true, "wrong.example:8086", false, http.StatusForbidden, RoleDeny},
		{"unavailable authority", []string{"http", "cli"}, "GET", true, "", true, http.StatusServiceUnavailable, RoleDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, d, mode := keeneticFixtureTags(t, tc.tags)
			if tc.unavailable {
				mode.Store(3)
			}
			var gotRole Role
			var gotUser string
			var gotSessionKey [32]byte
			s.Pages = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotRole = RoleFrom(r.Context())
				gotUser = KeeneticUserFrom(r.Context())
				gotSessionKey = KeeneticSessionKeyFrom(r.Context())
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.Method == http.MethodPost {
					d.applied = d.cfg
				}
				w.WriteHeader(http.StatusOK)
			})
			s.PageError = func(w http.ResponseWriter, _ *http.Request, status int) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(status)
				fmt.Fprintf(w, "<h1>%s</h1>", http.StatusText(status))
			}
			r := keeneticRequest(tc.method, "/connections", "", tc.session)
			if tc.method == "POST" {
				r.Header.Set("Origin", keeneticPanel)
			}
			if tc.host != "" {
				r.Host = tc.host
			}
			w := serve(s, r)
			if w.Code != tc.want || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || gotRole != tc.role {
				t.Fatalf("HTTP %d, %q, role %v, want %d, HTML, role %v", w.Code, w.Header().Get("Content-Type"), gotRole, tc.want, tc.role)
			}
			if tc.role != RoleDeny && gotUser != "operator" {
				t.Errorf("authorized account = %q, want operator", gotUser)
			}
			if (gotSessionKey != [32]byte{}) != (tc.role != RoleDeny) {
				t.Fatal("only the verified session should supply a draft binding")
			}
			if tc.want != http.StatusOK && (d.applied != nil || !strings.Contains(w.Body.String(), "<h1>")) {
				t.Error("refused page reached the write handler or lacked its HTML response")
			}
		})
	}
}

func TestOnlyCanonicalStaticReadsArePublic(t *testing.T) {
	s, _, _ := keeneticFixture(t)
	s.Pages = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for _, tc := range []struct {
		method, path, peer string
		status             int
	}{
		{"GET", "/static/style.css", lan, http.StatusOK},
		{"HEAD", "/static/fonts/roboto-latin-400-normal.woff2", lan, http.StatusOK},
		{"GET", "/static/style.css", "203.0.113.12:5000", http.StatusForbidden},
		{"GET", "/staticish/style.css", lan, http.StatusUnauthorized},
		{"GET", "/static%2F..", lan, http.StatusUnauthorized},
		{"GET", "/static%2Fstyle.css", lan, http.StatusUnauthorized},
		{"GET", "/st%61tic/app.js", lan, http.StatusUnauthorized},
		{"GET", "/static/%2e%2e/style.css", lan, http.StatusUnauthorized},
		{"GET", "/static/../style.css", lan, http.StatusUnauthorized},
		{"POST", "/static/style.css", lan, http.StatusUnauthorized},
	} {
		r := keeneticRequest(tc.method, tc.path, "", false)
		r.RemoteAddr = tc.peer
		r.Header.Set("Origin", keeneticPanel)
		if w := serve(s, r); w.Code != tc.status {
			t.Errorf("%s %s from %s = %d, want %d", r.Method, tc.path, tc.peer, w.Code, tc.status)
		}
	}
}

// Ruling R15: while an SSH tunnel is open, a page the admin visits must not
// drive the loopback control API. Every write from a cross-origin browser
// context is refused before trust is decided; same-origin pages and clients
// without browser headers (curl, the integration and memory gates) still work.
func TestCrossOriginWritesAreRefusedEvenFromLoopback(t *testing.T) {
	s, d := newServer()
	var pagePosts int
	s.Pages = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/routing" {
			pagePosts++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
	for _, rt := range append(s.routes(), route{pattern: "POST /routing"}) {
		method, _ := routeMethod(rt.pattern)
		methods := []string{method}
		if method == "" {
			methods = []string{http.MethodPost, http.MethodPut, http.MethodDelete}
		}
		for _, m := range methods {
			if m == http.MethodGet {
				continue
			}
			for _, path := range routePaths(rt.pattern) {
				for _, headers := range []map[string]string{
					{"Origin": "https://evil.example"},
					{"Sec-Fetch-Site": "cross-site"},
					{"Sec-Fetch-Site": "same-site", "Origin": "http://127.0.0.1:3000"},
					{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
				} {
					r := httptest.NewRequest(m, "http://127.0.0.1:8086"+path, strings.NewReader(roleConfig))
					r.RemoteAddr, r.Host = local, "127.0.0.1:8086"
					r.Header.Set("Content-Type", "text/plain")
					for k, v := range headers {
						r.Header.Set(k, v)
					}
					if w := serve(s, r); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "cross-origin request denied") {
						t.Errorf("%s %s with %v: %d %q", m, path, headers, w.Code, w.Body)
					}
				}
			}
		}
	}
	if d.applied != nil || pagePosts != 0 {
		t.Fatal("a cross-origin write applied settings or reached the page handler")
	}
	pagePost := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8086/routing", nil)
	pagePost.RemoteAddr = local
	pagePost.Header.Set("Origin", "http://127.0.0.1:8086")
	if w := serve(s, pagePost); w.Code != http.StatusNoContent || pagePosts != 1 {
		t.Fatalf("same-origin page POST: HTTP %d, handler calls %d", w.Code, pagePosts)
	}
	for _, headers := range []map[string]string{
		nil,
		{"Origin": "http://127.0.0.1:8086"},
		{"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:8086"},
	} {
		d.applied = nil
		r := httptest.NewRequest("PUT", "/api/config", strings.NewReader(roleConfig))
		r.RemoteAddr, r.Host = local, "127.0.0.1:8086"
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		if w := serve(s, r); w.Code != http.StatusOK || d.applied == nil {
			t.Errorf("loopback PUT /api/config with %v: %d %s", headers, w.Code, w.Body)
		}
	}
}
