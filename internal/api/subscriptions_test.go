package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestSubscriptionAPIAuthenticationAndOfflineStatus(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	const path = "/api/subscriptions/status"
	if w := do(t, h, http.MethodGet, path, "", "", lan); w.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated subscription status returned %d", w.Code)
	}
	if w := do(t, h, http.MethodGet, path, "", "secret", local); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("offline status returned %d %s", w.Code, w.Body.String())
	}
}

type subscriptionFixture struct {
	*fakeDaemon
}

func (f subscriptionFixture) PreviewSubscription(_ context.Context, source subscription.Source) daemon.SubscriptionStatus {
	return daemon.SubscriptionStatus{
		ID: source.ID, State: "hwid_limit",
		Metadata: subscription.Metadata{Announce: "Device limit reached"},
	}
}

func (f subscriptionFixture) Subscriptions() []daemon.SubscriptionStatus {
	return nil
}

func (f subscriptionFixture) RefreshSubscription(string) bool {
	return false
}

func TestSubscriptionPreviewReportsProviderLimitWithoutSaving(t *testing.T) {
	s, d := newServer()
	s.D = subscriptionFixture{d}
	const path = "/api/subscriptions/preview"
	const input = `{"id":"provider","url":"https://provider.example/sub/example-token","send_hwid":true}`
	h := s.Handler()
	post := func(body, contentType string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.RemoteAddr = local
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := post(input, "application/json")
	var response daemon.SubscriptionStatus
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatalf("preview request returned %d %s", w.Code, w.Body.String())
	}
	if response.ID != "provider" || response.State != "hwid_limit" || response.Metadata.Announce != "Device limit reached" {
		t.Fatalf("provider status not reported: %+v", response)
	}
	if len(d.cfg.Subscriptions) != 0 || d.applied != nil || strings.Contains(w.Body.String(), "example-token") {
		t.Fatal("preview saved configuration or exposed the source URL")
	}
	if w := post(strings.Replace(input, "https://", "http://", 1), "application/json"); w.Code != http.StatusBadRequest {
		t.Fatalf("unsecured URL returned %d", w.Code)
	}
	if w := post(input, "text/plain"); w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON media type returned %d", w.Code)
	}
}

func TestSubscriptionMutationRejectsForeignOriginFromTrustedLAN(t *testing.T) {
	s, d := newServer()
	d.cfg.API.NoTokenFrom = []string{"192.168.7.0/24"}
	s.D = subscriptionFixture{d}
	h := s.Handler()
	for _, path := range []string{"/api/subscriptions/preview", "/api/subscriptions/provider/refresh", "/api/subscriptions/provider/check"} {
		request := httptest.NewRequest(http.MethodPost, "http://router.test"+path,
			strings.NewReader(`{"id":"provider","url":"https://provider.example/list"}`))
		request.RemoteAddr = local
		request.Header.Set("Content-Type", "text/plain")
		request.Header.Set("Origin", "https://other.example")
		request.Header.Set("Sec-Fetch-Site", "cross-site")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Errorf("%s cross-origin request returned %d", path, response.Code)
		}
	}
}

type savedSubscriptionChecker struct {
	*fakeDaemon
}

func (savedSubscriptionChecker) CheckSubscription(source, node string) bool {
	return source == "saved" && (node == "" || node == strings.Repeat("a", 32))
}

func TestSubscriptionCheckRequestUsesOnlyAppliedNodeIDs(t *testing.T) {
	s, d := newServer()
	s.D = savedSubscriptionChecker{d}
	handler := s.Handler()
	for _, tc := range []struct {
		source, body, contentType, token string
		want                             int
	}{
		{"saved", "{}", "application/json", "secret", http.StatusAccepted},
		{"saved", "{\"node_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", "application/json", "secret", http.StatusAccepted},
		{"saved", "{\"node_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}", "application/json", "secret", http.StatusNotFound},
		{"missing", "{}", "application/json", "secret", http.StatusNotFound},
		{"saved", "{\"node_id\":\"auto\"}", "application/json", "secret", http.StatusBadRequest},
		{"saved", "{\"url\":\"https://external.example/\"}", "application/json", "secret", http.StatusBadRequest},
		{"saved", "null", "application/json", "secret", http.StatusBadRequest},
		{"saved", "{\"node_id\":null}", "application/json", "secret", http.StatusBadRequest},
		{"saved", "{}", "text/plain", "secret", http.StatusUnsupportedMediaType},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/subscriptions/"+tc.source+"/check", strings.NewReader(tc.body))
		r.RemoteAddr = local
		r.Header.Set("Authorization", "Bearer "+tc.token)
		r.Header.Set("Content-Type", tc.contentType)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s returned %d, want %d", tc.source, tc.body, w.Code, tc.want)
		}
		if tc.want == http.StatusAccepted && strings.TrimSpace(w.Body.String()) != "{\"ok\":true}" {
			t.Errorf("accepted response did not confirm scheduling: %s", w.Body)
		}
	}
}
