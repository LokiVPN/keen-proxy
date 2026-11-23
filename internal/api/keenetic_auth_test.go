package api

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/journal"
)

const (
	keeneticPanel = "http://192.168.7.1:8086"
	routerCookie  = "router-fixture-session"
	routerSession = "fixture-session-value"
)

// The authority returns the wire format observed on KeeneticOS 5.1.
func keeneticFixture(t *testing.T) (*Server, *fakeDaemon, *atomic.Int32) {
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
			if mode.Load() == 1 {
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
	d.cfg.API.NoTokenFrom = []string{"192.168.7.0/24"}
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

	stale := keeneticRequest("GET", "/api/status", "", false)
	stale.AddCookie(&http.Cookie{Name: cookieName, Value: s.Token})
	call(stale, http.StatusUnauthorized)
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
	call(keeneticRequest("GET", "/api/config", "", true), http.StatusForbidden)
	mode.Store(3)
	call(keeneticRequest("GET", "/api/config", "", true), http.StatusServiceUnavailable)
	mode.Store(2)
	call(keeneticRequest("GET", "/api/config", "", true), http.StatusUnauthorized)

	automation := keeneticRequest("GET", "/api/status", "", false)
	automation.Header.Set("Authorization", "Bearer "+s.Token)
	call(automation, http.StatusOK)
}

func TestKeeneticLogoutRevokesSessionAndStopsJournal(t *testing.T) {
	s, d, _ := keeneticFixture(t)
	h := httptest.NewServer(s.Handler())
	t.Cleanup(h.Close)
	client := h.Client()
	client.Timeout = 4 * time.Second
	req, err := http.NewRequestWithContext(t.Context(), "GET", h.URL+"/api/journal/audit/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "192.168.7.1:8086"
	req.AddCookie(&http.Cookie{Name: routerCookie, Value: routerSession})
	stream, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	lines := bufio.NewReader(stream.Body)
	if line, err := lines.ReadString('\n'); stream.StatusCode != http.StatusOK || err != nil || line != ": ok\n" {
		t.Fatalf("could not open authorized journal stream: %q, %v", line, err)
	}

	logout := keeneticRequest("POST", "/api/logout", "", true)
	logout.Header.Set("Origin", keeneticPanel)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, logout)
	if w.Code != http.StatusOK {
		t.Fatalf("sign out: HTTP %d (%s)", w.Code, w.Body)
	}
	d.journals[journal.Audit].Add(journal.Entry{Message: "post-logout test event"})
	tail, err := io.ReadAll(lines)
	if err != nil || strings.Contains(string(tail), "post-logout test event") {
		t.Fatalf("journal after sign-out: %q, %v", tail, err)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, keeneticRequest("GET", "/api/status", "", true))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("the old session still opens the API: HTTP %d", w.Code)
	}
}
