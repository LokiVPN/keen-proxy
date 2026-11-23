package api

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"regexp"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

var subscriptionNodeID = regexp.MustCompile("^[a-f0-9]{32}$")

// subscriptionDaemon separates read and refresh operations from draft Apply.
type subscriptionDaemon interface {
	PreviewSubscription(context.Context, subscription.Source) daemon.SubscriptionStatus
	Subscriptions() []daemon.SubscriptionStatus
	RefreshSubscription(id string) bool
}

func (s *Server) subscriptionStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	status := []daemon.SubscriptionStatus{}
	if d, ok := s.D.(subscriptionDaemon); ok {
		status = append(status, d.Subscriptions()...)
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) subscriptionPreview(w http.ResponseWriter, r *http.Request) {
	if !allowSubscriptionPost(w, r) {
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "subscription preview requires application/json")
		return
	}
	var source subscription.Source
	if err := decodeJSONRequest(w, r, 16<<10, &source); err != nil {
		writeError(w, http.StatusBadRequest, "invalid subscription preview request")
		return
	}
	if err := subscription.ValidateSource(source); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d, ok := s.D.(subscriptionDaemon)
	if !ok {
		writeError(w, http.StatusNotImplemented, "subscription preview requires a live backend")
		return
	}
	writeJSON(w, http.StatusOK, d.PreviewSubscription(r.Context(), source))
}

func (s *Server) subscriptionRefresh(w http.ResponseWriter, r *http.Request) {
	if !allowSubscriptionPost(w, r) {
		return
	}
	d, ok := s.D.(subscriptionDaemon)
	if !ok {
		writeError(w, http.StatusNotImplemented, "subscription refresh requires a live backend")
		return
	}
	if !d.RefreshSubscription(r.PathValue("id")) {
		writeError(w, http.StatusNotFound, "subscription is not applied")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// subscriptionCheck accepts an applied node identity, or an empty object for
// the whole saved catalog. Probe destinations come from the router settings.
func (s *Server) subscriptionCheck(w http.ResponseWriter, r *http.Request) {
	if !allowSubscriptionPost(w, r) {
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "subscription check requires application/json")
		return
	}
	var request *struct {
		NodeID json.RawMessage `json:"node_id"`
	}
	if err := decodeJSONRequest(w, r, 1<<10, &request); err != nil || request == nil {
		writeError(w, http.StatusBadRequest, "invalid subscription check request")
		return
	}
	var node string
	if request.NodeID != nil && (json.Unmarshal(request.NodeID, &node) != nil || !subscriptionNodeID.MatchString(node)) {
		writeError(w, http.StatusBadRequest, "invalid subscription node ID")
		return
	}
	d, ok := s.D.(interface{ CheckSubscription(string, string) bool })
	if !ok || !d.CheckSubscription(r.PathValue("id"), node) {
		writeError(w, http.StatusNotFound, "applied subscription node or catalog is unavailable")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

// allowSubscriptionPost rejects cross-origin browser requests, such as another
// page posting with a signed-in KeeneticOS session, before a preview, refresh
// or check can contact the provider and register the router's HWID.
func allowSubscriptionPost(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if err := browserOrigin.Check(r); err != nil {
		writeError(w, http.StatusForbidden, "cross-origin subscription request denied")
		return false
	}
	return true
}
