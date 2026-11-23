package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/update"
)

func TestUpdatePermissions(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	for _, tc := range []struct {
		name, method, path, body, token, origin string
		want                                    int
	}{
		{"loopback status", "GET", "/api/updates", "", "", "", 200},
		{"loopback check", "POST", "/api/updates/check", "{}", "", "", 200},
		{"blocks cross-origin install", "POST", "/api/updates/install", `{"target":"v0.4.0"}`, "secret", "http://evil.example", 403},
		{"demo cannot configure updates", "PUT", "/api/updates/preferences", `{"time":"04:00"}`, "secret", "", 409},
		{"invalid schedule is rejected", "PUT", "/api/updates/preferences", `{"time":7}`, "secret", "", 400},
		{"demo cannot install", "POST", "/api/updates/install", `{"target":"v0.4.0"}`, "secret", "", 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.RemoteAddr = local
			r.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body)
			}
		})
	}
}

func TestUpdateOperationsRefuseLANPeers(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/api/updates/preferences", `{"time":"04:00"}`},
		{"POST", "/api/updates/install", `{"target":"v0.4.0"}`},
	} {
		if w := do(t, h, tc.method, tc.path, tc.body, "secret", lan); w.Code != http.StatusForbidden {
			t.Errorf("%s %s from LAN: %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestUpdateErrorsDoNotExposeInstallerDetails(t *testing.T) {
	s, _ := newServer()
	w := httptest.NewRecorder()
	s.updateError(w, errors.New("private installer error"))
	if w.Code != 500 || strings.Contains(w.Body.String(), "private installer error") {
		t.Fatalf("internal error was not safely reported: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.updateError(w, update.ErrPreferences)
	if w.Code != 400 {
		t.Fatalf("invalid preferences returned %d", w.Code)
	}
}
