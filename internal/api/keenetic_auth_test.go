package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
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

func TestKeeneticSessionAuthorizesAPIAndRevokesAccess(t *testing.T) {
	s, d, mode := keeneticFixture(t)
	h := s.Handler()
	call := func(r *http.Request, status int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: got %d, want %d (%s)", r.Method, r.URL.Path, w.Code, status, w.Body)
		}
		return w
	}

	call(keeneticRequest("GET", "/api/status", "", false), http.StatusUnauthorized)
	call(keeneticRequest("GET", "/api/status", "", true), http.StatusOK)

	view := call(keeneticRequest("GET", "/api/session", "", true), http.StatusOK)
	var session struct {
		Authed      bool   `json:"authed"`
		KeeneticURL string `json:"keenetic_url"`
	}
	if err := json.Unmarshal(view.Body.Bytes(), &session); err != nil || !session.Authed || session.KeeneticURL == "" {
		t.Fatalf("browser session: %s", view.Body)
	}

	const config = `{"groups":[{"name":"test","target":"direct","entries":["example.com"]}]}`
	write := keeneticRequest("PUT", "/api/config", config, true)
	write.Header.Set("Origin", "http://192.168.7.1")
	call(write, http.StatusForbidden)
	if d.applied != nil {
		t.Fatal("cross-origin request applied settings")
	}
	write.Header.Set("Origin", keeneticPanel)
	call(write, http.StatusOK)
	if d.applied == nil || d.applied.Groups[0].Entries[0] != "example.com" {
		t.Fatal("a verified management session could not apply settings")
	}

	mode.Store(1)
	call(keeneticRequest("GET", "/api/config", "", true), http.StatusOK)
	mode.Store(3)
	call(keeneticRequest("GET", "/api/config", "", true), http.StatusServiceUnavailable)
	mode.Store(2)
	call(keeneticRequest("GET", "/api/config", "", true), http.StatusUnauthorized)

	automation := keeneticRequest("GET", "/api/status", "", false)
	automation.Header.Set("Authorization", "Bearer secret")
	call(automation, http.StatusUnauthorized)

	local := keeneticRequest("GET", "/api/status", "", false)
	local.RemoteAddr, local.Host = "127.0.0.1:5000", "127.0.0.1:8086"
	call(local, http.StatusOK)
}

func TestKeeneticLogoutRevokesSession(t *testing.T) {
	s, _, _ := keeneticFixture(t)
	journalGet := func() int {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, keeneticRequest("GET", "/api/journal/audit", "", true))
		return w.Code
	}
	if code := journalGet(); code != http.StatusOK {
		t.Fatalf("authorized journal: HTTP %d", code)
	}
	logout := keeneticRequest("POST", "/api/logout", "", true)
	logout.Header.Set("Origin", keeneticPanel)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, logout)
	if w.Code != http.StatusOK {
		t.Fatalf("sign out: HTTP %d (%s)", w.Code, w.Body)
	}
	if code := journalGet(); code != http.StatusUnauthorized {
		t.Fatalf("journal after sign-out: HTTP %d", code)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, keeneticRequest("GET", "/api/status", "", true))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("the old session still opens the API: HTTP %d", w.Code)
	}
}

const roleConfig = `{"groups":[{"name":"test","target":"direct","entries":["example.com"]}]}`

func roleWrite() *http.Request {
	r := keeneticRequest("PUT", "/api/config", roleConfig, true)
	r.Header.Set("Origin", keeneticPanel)
	return r
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func checkViewOnly(t *testing.T, tags []string) {
	t.Helper()
	s, d, _ := keeneticFixtureTags(t, tags)
	if w := serve(s, keeneticRequest("GET", "/api/status", "", true)); w.Code != http.StatusOK {
		t.Fatalf("read: got %d (%s)", w.Code, w.Body)
	}
	w := serve(s, roleWrite())
	if w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != `{"error":"KeeneticOS management access denied"}` {
		t.Fatalf("write: got %d %s", w.Code, w.Body)
	}
	if d.applied != nil {
		t.Fatal("a view role applied settings")
	}
}

func TestReadOnlyAccountCanReadButNotWrite(t *testing.T) {
	checkViewOnly(t, []string{"http", "readonly"})
}

func TestManagerAccountIsViewOnly(t *testing.T) {
	checkViewOnly(t, []string{"http", "cli", "manager"})
}

func TestAdministratorCanWrite(t *testing.T) {
	s, d, _ := keeneticFixtureTags(t, []string{"http", "cli"})
	if w := serve(s, roleWrite()); w.Code != http.StatusOK || d.applied == nil {
		t.Fatalf("write: got %d (%s)", w.Code, w.Body)
	}
}

func TestUnknownTagsAreDenied(t *testing.T) {
	s, _, _ := keeneticFixtureTags(t, []string{"http"})
	if w := serve(s, keeneticRequest("GET", "/api/status", "", true)); w.Code != http.StatusForbidden {
		t.Fatalf("got %d (%s)", w.Code, w.Body)
	}
}

func TestRoleFromReportsTheAuthorizedRole(t *testing.T) {
	if RoleFrom(context.Background()) != RoleDeny {
		t.Fatal("a request without a decision must be denied")
	}
	probe := func(s *Server, r *http.Request) Role {
		var got Role
		serve := s.authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = RoleFrom(r.Context()) }))
		serve.ServeHTTP(httptest.NewRecorder(), r)
		return got
	}
	s, _, _ := keeneticFixtureTags(t, []string{"http", "readonly"})
	if got := probe(s, keeneticRequest("GET", "/api/x", "", true)); got != RoleView {
		t.Fatalf("session role %v", got)
	}
	local := keeneticRequest("GET", "/api/x", "", false)
	local.RemoteAddr, local.Host = "127.0.0.1:5000", "127.0.0.1:8086"
	if got := probe(s, local); got != RoleManage {
		t.Fatalf("loopback role %v", got)
	}
}

func TestMyKeeneticHostAccepted(t *testing.T) {
	s, _, _ := keeneticFixture(t)
	r := keeneticRequest("GET", "/api/status", "", true)
	r.Host = "my.keenetic.net:8086"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("my.keenetic.net with the panel port: %d", w.Code)
	}
}

func TestOtherHostRejected(t *testing.T) {
	s, _, _ := keeneticFixture(t)
	for _, host := range []string{"my.keenetic.net", "my.keenetic.net:80", "evil.example:8086", "192.168.7.1", "192.168.7.2:8086", "my.keenetic.net.evil.example:8086"} {
		r := keeneticRequest("GET", "/api/status", "", true)
		r.Host = host
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("Host %q: %d, want 403", host, w.Code)
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
