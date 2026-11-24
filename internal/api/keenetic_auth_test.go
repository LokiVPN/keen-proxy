package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	keeneticPanel = "http://192.168.7.1:8086"
	routerCookie  = "router-fixture-session"
	routerSession = "fixture-session-value"
)

// The authority returns the wire format observed on KeeneticOS 5.1.
func keeneticFixture(t *testing.T) (*Server, *fakeDaemon, *atomic.Int32) {
	t.Helper()
	return keeneticFixtureTags(t, nil)
}

// keeneticFixtureTags is keeneticFixture with the account's tags fixed when
// tags is non-nil; mode 1 still adds readonly to the default tags.
func keeneticFixtureTags(t *testing.T, accountTags []string) (*Server, *fakeDaemon, *atomic.Int32) {
	t.Helper()
	var mode atomic.Int32
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || len(r.Cookies()) > 1 {
			t.Error("unrelated credentials reached the router authority")
		}
		cookie, _ := r.Cookie(routerCookie)
		if r.URL.Path == "/auth" && r.Method == http.MethodGet && cookie == nil {
			w.Header().Set("X-Ndm-Challenge", "fixture-challenge")
			w.Header().Set("X-Ndm-Realm", "fixture-realm")
			http.SetCookie(w, &http.Cookie{Name: routerCookie, Value: "initial", HttpOnly: true, Path: "/"})
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if mode.Load() == 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if mode.Load() == 2 || cookie == nil || cookie.Value != routerSession {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/auth":
			if r.Method != http.MethodDelete {
				t.Errorf("unexpected session operation %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			mode.Store(2)
		case "/rci/whoami":
			writeJSON(w, http.StatusOK, map[string]string{"user": "operator"})
		case "/rci/show/sc/user":
			if r.URL.Query().Get("name") != "operator" {
				t.Error("roles must be scoped to the authenticated account")
			}
			tags := []string{"http", "cli"}
			if accountTags != nil {
				tags = accountTags
			} else if mode.Load() == 1 {
				tags = append(tags, "readonly")
			}
			writeJSON(w, http.StatusOK, map[string]any{"operator": map[string]any{"tag": tags}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(authority.Close)
	origin, err := url.Parse(authority.URL)
	if err != nil {
		t.Fatal(err)
	}
	s, d := newServer()
	s.Keenetic = newKeeneticAuth(origin, "192.168.7.1:8086", authority.Client())
	return s, d, &mode
}

func keeneticRequest(method, path, body string, withSession bool) *http.Request {
	r := httptest.NewRequest(method, keeneticPanel+path, strings.NewReader(body))
	r.RemoteAddr = lan
	if withSession {
		r.AddCookie(&http.Cookie{Name: routerCookie, Value: routerSession})
	}
	return r
}

// A KeeneticOS session opens pages, never the control API, and losing the
// router session closes the pages again.
func TestKeeneticSessionOpensPagesNotTheControlAPI(t *testing.T) {
	s, d, mode := keeneticFixture(t)
	s.Pages = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("panel"))
	})
	call := func(r *http.Request, status int, body string) {
		t.Helper()
		if w := serve(s, r); w.Code != status || !strings.Contains(w.Body.String(), body) {
			t.Fatalf("%s %s: got %d %q, want %d %q", r.Method, r.URL.Path, w.Code, w.Body, status, body)
		}
	}
	call(keeneticRequest("GET", "/", "", false), http.StatusUnauthorized, "KeeneticOS sign-in required")
	call(keeneticRequest("GET", "/", "", true), http.StatusOK, "panel")
	call(keeneticRequest("GET", "/api/status", "", true), http.StatusForbidden, "local access only")

	view := serve(s, keeneticRequest("GET", "/api/session", "", true))
	var session struct {
		Authed      bool   `json:"authed"`
		KeeneticURL string `json:"keenetic_url"`
	}
	if err := json.Unmarshal(view.Body.Bytes(), &session); err != nil || !session.Authed || session.KeeneticURL == "" {
		t.Fatalf("browser session: %s", view.Body)
	}

	write := keeneticRequest("PUT", "/api/config", roleConfig, true)
	write.Header.Set("Origin", keeneticPanel)
	call(write, http.StatusForbidden, "local access only")
	if d.applied != nil {
		t.Fatal("a browser session applied settings through the control API")
	}

	mode.Store(3)
	call(keeneticRequest("GET", "/", "", true), http.StatusServiceUnavailable, "KeeneticOS session check unavailable")
	mode.Store(2)
	call(keeneticRequest("GET", "/", "", true), http.StatusUnauthorized, "KeeneticOS sign-in required")

	automation := keeneticRequest("GET", "/api/status", "", false)
	automation.Header.Set("Authorization", "Bearer secret")
	call(automation, http.StatusForbidden, "local access only")

	local := keeneticRequest("GET", "/api/status", "", false)
	local.RemoteAddr, local.Host = "127.0.0.1:5000", "127.0.0.1:8086"
	call(local, http.StatusOK, `"build"`)
}

func TestKeeneticLogoutRevokesSession(t *testing.T) {
	for _, tc := range []struct {
		name, accept, contentType string
		status                    int
	}{
		{"API response", "application/json", "", http.StatusOK},
		{"HTML navigation", "text/html,application/xhtml+xml,*/*;q=0.8", "", http.StatusSeeOther},
		{"HTML form", "", "application/x-www-form-urlencoded", http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := keeneticFixture(t)
			if role, w := pageRole(s, keeneticRequest("GET", "/connections", "", true)); role != RoleManage {
				t.Fatalf("signed-in page: role %v, %d %s", role, w.Code, w.Body)
			}
			logout := keeneticRequest("POST", "/api/logout", "", true)
			logout.Header.Set("Origin", keeneticPanel)
			logout.Header.Set("Accept", tc.accept)
			logout.Header.Set("Content-Type", tc.contentType)
			w := serve(s, logout)
			if w.Code != tc.status {
				t.Fatalf("sign out: HTTP %d (%s), want %d", w.Code, w.Body, tc.status)
			}
			if tc.status == http.StatusSeeOther {
				if location := w.Header().Get("Location"); location != "/" {
					t.Fatalf("sign out redirect = %q, want /", location)
				}
			} else if strings.TrimSpace(w.Body.String()) != "{\"ok\":true}" {
				t.Fatalf("sign out JSON = %q", w.Body)
			}
			if role, w := pageRole(s, keeneticRequest("GET", "/connections", "", true)); role != RoleDeny || w.Code != http.StatusUnauthorized {
				t.Fatalf("the old session still opens pages: role %v, %d %s", role, w.Code, w.Body)
			}
		})
	}
}

// Through an SSH tunnel there is no router session to drop: signing out from
// trusted loopback succeeds without touching the router.
func TestLoopbackLogoutSucceedsInKeeneticMode(t *testing.T) {
	s, _, mode := keeneticFixture(t)
	r := keeneticRequest("POST", "/api/logout", "", false)
	r.RemoteAddr, r.Host = local, "127.0.0.1:8086"
	r.Header.Set("Origin", "http://127.0.0.1:8086")
	if w := serve(s, r); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
		t.Fatalf("loopback sign-out: %d %s", w.Code, w.Body)
	}
	if mode.Load() != 0 {
		t.Fatal("loopback sign-out changed the router session")
	}
}

const roleConfig = `{"groups":[{"name":"test","target":"direct","entries":["example.com"]}]}`

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// pageRole sends r through the access policy to a page handler and returns
// the role that handler sees (RoleDeny when it was never called) and the
// response.
func pageRole(s *Server, r *http.Request) (Role, *httptest.ResponseRecorder) {
	got := RoleDeny
	page := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = RoleFrom(r.Context()) })
	w := httptest.NewRecorder()
	s.lanOnly(s.authorize(page)).ServeHTTP(w, r)
	return got, w
}

// pageWrite is a same-origin form post from the panel address.
func pageWrite() *http.Request {
	r := keeneticRequest("POST", "/connections", "", true)
	r.Header.Set("Origin", keeneticPanel)
	return r
}

func checkViewOnly(t *testing.T, tags []string) {
	t.Helper()
	s, _, _ := keeneticFixtureTags(t, tags)
	if role, w := pageRole(s, keeneticRequest("GET", "/connections", "", true)); role != RoleView {
		t.Fatalf("read: role %v, %d %s", role, w.Code, w.Body)
	}
	role, w := pageRole(s, pageWrite())
	if role != RoleDeny || w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != "KeeneticOS management access denied" {
		t.Fatalf("write: role %v, %d %s", role, w.Code, w.Body)
	}
}

func TestReadOnlyAccountCanReadButNotWrite(t *testing.T) {
	checkViewOnly(t, []string{"http", "readonly"})
}

func TestManagerAccountIsViewOnly(t *testing.T) {
	checkViewOnly(t, []string{"http", "cli", "manager"})
}

func TestAdministratorCanWrite(t *testing.T) {
	s, _, _ := keeneticFixtureTags(t, []string{"http", "cli"})
	if role, w := pageRole(s, pageWrite()); role != RoleManage {
		t.Fatalf("write: role %v, %d %s", role, w.Code, w.Body)
	}
}

func TestUnknownTagsAreDenied(t *testing.T) {
	s, _, _ := keeneticFixtureTags(t, []string{"http"})
	if role, w := pageRole(s, keeneticRequest("GET", "/connections", "", true)); role != RoleDeny || w.Code != http.StatusForbidden {
		t.Fatalf("got role %v, %d (%s)", role, w.Code, w.Body)
	}
}

func TestRoleFromReportsTheAuthorizedRole(t *testing.T) {
	if RoleFrom(context.Background()) != RoleDeny {
		t.Fatal("a request without a decision must be denied")
	}
	s, _, _ := keeneticFixtureTags(t, []string{"http", "readonly"})
	if got, _ := pageRole(s, keeneticRequest("GET", "/x", "", true)); got != RoleView {
		t.Fatalf("session role %v", got)
	}
	local := keeneticRequest("GET", "/api/x", "", false)
	local.RemoteAddr, local.Host = "127.0.0.1:5000", "127.0.0.1:8086"
	if got, _ := pageRole(s, local); got != RoleManage {
		t.Fatalf("loopback role %v", got)
	}
}

func TestMyKeeneticHostAccepted(t *testing.T) {
	s, _, _ := keeneticFixture(t)
	r := keeneticRequest("GET", "/connections", "", true)
	r.Host = "my.keenetic.net:8086"
	if role, w := pageRole(s, r); role != RoleManage {
		t.Fatalf("my.keenetic.net with the panel port: role %v, %d", role, w.Code)
	}
}

func TestOtherHostRejected(t *testing.T) {
	s, _, _ := keeneticFixture(t)
	for _, host := range []string{"my.keenetic.net", "my.keenetic.net:80", "evil.example:8086", "192.168.7.1", "192.168.7.2:8086", "my.keenetic.net.evil.example:8086"} {
		r := keeneticRequest("GET", "/connections", "", true)
		r.Host = host
		if role, w := pageRole(s, r); role != RoleDeny || w.Code != http.StatusForbidden {
			t.Errorf("Host %q: role %v, %d, want 403", host, role, w.Code)
		}
	}
}

func TestUnavailableServiceDeniesBrowsersWith503(t *testing.T) {
	s, _ := newServer()
	s.Unavailable = true
	h := s.Handler()
	if c := do(t, h, "GET", "/api/status", "", "", lan).Code; c != http.StatusServiceUnavailable {
		t.Errorf("LAN peer: %d, want 503", c)
	}
	r := httptest.NewRequest("GET", "/api/status", nil)
	r.RemoteAddr, r.Host = "127.0.0.1:5000", "127.0.0.1:8086"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("loopback: %d, want 200", w.Code)
	}
}

func TestMyKeeneticHostWritePath(t *testing.T) {
	for _, tc := range []struct {
		origin string
		want   Role
	}{
		{"http://my.keenetic.net:8086", RoleManage},
		{"http://192.168.7.1:8086", RoleDeny},
	} {
		s, _, _ := keeneticFixture(t)
		r := pageWrite()
		r.Host = "my.keenetic.net:8086"
		r.Header.Set("Origin", tc.origin)
		if role, w := pageRole(s, r); role != tc.want || (role == RoleDeny && w.Code != http.StatusForbidden) {
			t.Errorf("Origin %s: role %v, %d %s, want %v", tc.origin, role, w.Code, w.Body, tc.want)
		}
	}
}

// The control API is loopback-only (ruling R14): whichever account signed in
// and whichever route it calls, a browser on the LAN never receives the
// subscription URL, a private key or a journal entry.
func TestBrowserResponsesNeverCarrySecrets(t *testing.T) {
	secrets := []string{"subscription-secret-fixture", "wireguard-key-secret-fixture", "journal-secret-fixture"}
	seed := func(d *fakeDaemon) {
		d.cfg = &model.Config{}
		d.cfg.Defaults()
		d.cfg.Subscriptions = []subscription.Source{{ID: "loki", URL: "https://provider.example/sub/" + secrets[0]}}
		d.cfg.Connections = []model.Connection{{ID: "wg", Name: "WG", Type: model.ConnWireGuard,
			WireGuard: &model.WireGuard{PrivateKey: secrets[1], Address: []string{"10.0.0.2/32"}}}}
		for _, kind := range journal.Kinds {
			d.journals[kind].Add(journal.Entry{Action: "fixture", Details: "password " + secrets[2], Message: secrets[2], Host: secrets[2]})
		}
	}
	for _, account := range []struct {
		name    string
		tags    []string
		session bool
	}{
		{"manage", []string{"http", "cli"}, true},
		{"view", []string{"http", "readonly"}, true},
		{"no session", []string{"http", "cli"}, false},
	} {
		s, d, mode := keeneticFixtureTags(t, account.tags)
		for _, rt := range s.routes() {
			method, _ := routeMethod(rt.pattern)
			methods := []string{method}
			if method == "" {
				methods = []string{http.MethodGet, http.MethodPost}
			}
			for _, method := range methods {
				for _, path := range routePaths(rt.pattern) {
					seed(d)
					mode.Store(0) // a previous logout revoked the router session
					r := keeneticRequest(method, path, "{}", account.session)
					r.Header.Set("Origin", keeneticPanel)
					r.Header.Set("Content-Type", "application/json")
					w := serve(s, r)
					for _, secret := range secrets {
						if strings.Contains(w.Body.String(), secret) {
							t.Errorf("%s: %s %s disclosed %q: %d", account.name, method, path, secret, w.Code)
						}
					}
					if !publicRoutes[method+" "+path] && w.Code/100 == 2 {
						t.Errorf("%s: %s %s answered a browser with %d", account.name, method, path, w.Code)
					}
				}
			}
		}
	}
}

func TestPanelListenConstraint(t *testing.T) {
	isLocal := func(a netip.Addr) bool { return a == netip.MustParseAddr("192.168.7.1") }
	for listen, ok := range map[string]bool{
		"0.0.0.0:8086": true, ":8086": true, "[::]:8086": true, "192.168.7.1:8086": true,
		"127.0.0.1:8086": false, "192.168.7.2:8086": false, "10.0.0.1:8086": false, "192.168.7.1:0": false, "bad": false,
	} {
		_, err := newKeeneticAuthFor("http://192.168.7.1", listen, isLocal)
		if (err == nil) != ok {
			t.Errorf("listen %q: error = %v, want ok = %t", listen, err, ok)
		}
	}
	if _, err := newKeeneticAuthFor("http://192.168.7.9", "0.0.0.0:8086", isLocal); err == nil {
		t.Error("an origin address not assigned to the router must be rejected")
	}
}
