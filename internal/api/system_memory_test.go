package api

import (
	"net/http"
	"runtime/debug"
	"strings"
	"testing"
)

// These tests observe process-wide state and must not run in parallel.
func holdMemoryLimit(t *testing.T) {
	t.Helper()
	before := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(before) })
}

// PUT /api/config is the only memory-limit route and still requires authentication.
func TestConfigRoutePreservesMemoryLimit(t *testing.T) {
	holdMemoryLimit(t)
	before := debug.SetMemoryLimit(-1)
	s, _ := newServer()
	h := s.Handler()

	body := `{"system":{"memory_limit_mib":400}}`
	if w := do(t, h, "PUT", "/api/config", body, "", lan); w.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated put: %d", w.Code)
	}
	w := do(t, h, "PUT", "/api/config", body, "secret", local)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"memory_limit_mib":400`) {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "GET", "/api/config", "", "secret", local)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"memory_limit_mib":400`) {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "PUT", "/api/config", `{"system":{"memory_limit_mib":0}}`, "secret", local)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("zero accepted: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "GET", "/api/config", "", "secret", local)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"memory_limit_mib":400`) {
		t.Fatalf("rejected put changed the stored limit: %d %s", w.Code, w.Body)
	}
	w = do(t, h, "PUT", "/api/config", `{"system":{"memory_limit_mib":null}}`, "secret", local)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "memory_limit_mib") {
		t.Fatalf("clear: %d %s", w.Code, w.Body)
	}
	if debug.SetMemoryLimit(-1) != before {
		t.Fatal("config route changed the process memory limit")
	}
}
