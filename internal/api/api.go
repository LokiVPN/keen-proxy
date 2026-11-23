// Package api serves the keenProxy HTTP API and web interface.
//
// The HTTP API under /api is a control API for local processes: it trusts
// only loopback peers that also address a loopback Host, and a KeeneticOS
// session opens nothing there but the session probe and sign-out. Pages
// (other paths) also admit verified KeeneticOS sessions when that sign-in mode
// is enabled. A separate address guard restricts access to private, loopback,
// and link-local peers even when the listening port is exposed.
package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/links"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/trusttunnel"
	"github.com/ordo-systems/keen-proxy/internal/update"
)

const maxConfigJSONBytes = 8 << 20

// Daemon defines the daemon capabilities used by the API and its test doubles.
type Daemon interface {
	Config() *model.Config
	Apply(ctx context.Context, cfg *model.Config) error
	Status(ctx context.Context) daemon.Status
	Devices() []daemon.Device
	Stats(withSeries bool) stats.Snapshot
	Hosts(tag, query string, limit int) ([]stats.Host, int)
	Journal(kind journal.Kind) *journal.Journal
}

// Server binds daemon operations and authentication policy.
type Server struct {
	D        Daemon
	Log      *slog.Logger
	Updates  *update.Manager
	Keenetic *KeeneticAuth
	// Unavailable refuses non-loopback requests with 503 when browser
	// sign-in could not be configured at startup.
	Unavailable bool

	supportBusy atomic.Bool
}

// route is one registered pattern and its endpoint.
type route struct {
	pattern string
	h       http.Handler
}

// publicRoutes are the only exact method and path pairs that skip
// authorization: they decide for themselves what to reveal (the session
// probe) or only drop a session. Stage 4 adds the sign-in page and a static
// asset prefix here.
var publicRoutes = map[string]bool{
	"GET /api/session": true,
	"POST /api/logout": true,
}

// routes lists every endpoint and the two catch-alls; Handler registers
// exactly this list.
func (s *Server) routes() []route {
	return append([]route{
		{"POST /api/diagnostics/check", http.HandlerFunc(s.diagnosticCheck)},
		{"GET /api/diagnostics/bundle", http.HandlerFunc(s.supportBundle)},
		{"GET /api/diagnostics/tproxy", http.HandlerFunc(s.tproxyReadiness)},
		{"POST /api/diagnostics/tproxy/retry", http.HandlerFunc(s.retryTProxy)},
		{"GET /api/subscriptions/status", http.HandlerFunc(s.subscriptionStatus)},
		{"POST /api/subscriptions/preview", http.HandlerFunc(s.subscriptionPreview)},
		{"POST /api/subscriptions/{id}/refresh", http.HandlerFunc(s.subscriptionRefresh)},
		{"POST /api/subscriptions/{id}/check", http.HandlerFunc(s.subscriptionCheck)},
		{"POST /api/logout", http.HandlerFunc(s.logout)},
		{"GET /api/session", http.HandlerFunc(s.session)},
		{"GET /api/status", http.HandlerFunc(s.status)},
		{"GET /api/config", http.HandlerFunc(s.getConfig)},
		{"PUT /api/config", http.HandlerFunc(s.putConfig)},
		{"POST /api/config/validate", http.HandlerFunc(s.validateConfig)},
		{"GET /api/devices", http.HandlerFunc(s.devices)},
		{"POST /api/links/parse", http.HandlerFunc(s.parseLink)},
		{"POST /api/amnezia/import", http.HandlerFunc(s.amneziaImport)},
		{"GET /api/stats", http.HandlerFunc(s.stats)},
		{"GET /api/stats/hosts", http.HandlerFunc(s.hosts)},
		{"GET /api/journal/{kind}", http.HandlerFunc(s.journalPage)},
	}, append(s.updateRoutes(),
		route{"/api/", http.NotFoundHandler()},
		route{"/", http.HandlerFunc(rebuildingUI)},
	)...)
}

// Handler builds the routes. The peer-address guard runs first, then the
// authorization middleware, so every path is protected unless it is listed
// in publicRoutes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		mux.Handle(rt.pattern, rt.h)
	}
	return s.lanOnly(s.authorize(mux))
}

// lanOnly accepts private, loopback, and link-local peers based on RemoteAddr.
func (s *Server) lanOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		a, err := netip.ParseAddr(host)
		if err != nil || !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()) {
			http.Error(w, "access restricted to local networks", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopback reports whether the request comes from a local process: a
// loopback RemoteAddr and a loopback Host. The Host check keeps a browser
// reaching the router through a DNS name or a LAN address from being trusted
// when a local reverse proxy forwards it. Other headers are untrusted.
func isLoopback(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback() && loopbackHost(r.Host)
}

// loopbackHost reports whether a Host header names 127.0.0.1, ::1 or
// localhost, with any port.
func loopbackHost(hostport string) bool {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		h = strings.Trim(hostport, "[]")
	}
	h = strings.ToLower(h)
	return h == "127.0.0.1" || h == "::1" || h == "localhost"
}

// isAPI reports whether path belongs to the control API, which answers in
// JSON; every other path is a page.
func isAPI(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

// verdict is the access decision for one request: the role it grants, or the
// refusal status and the reason shown to the client.
type verdict struct {
	role   Role
	status int    // http.StatusOK when granted
	reason string // empty when granted
}

// authorize is the single place that decides access. Every request except
// publicRoutes gets a verdict; a granted one carries its role in the context
// (see RoleFrom), a refused one gets the refusal as JSON under /api and as
// short text elsewhere, where stage 4 renders the sign-in screens. Nothing it
// passes on or refuses may be cached.
func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if publicRoutes[r.Method+" "+r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		v := s.decide(r)
		if v.status != http.StatusOK {
			if isAPI(r.URL.Path) {
				writeError(w, v.status, v.reason)
			} else {
				http.Error(w, v.reason, v.status)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), roleKey{}, v.role)))
	})
}

// decide applies the access policy: trusted loopback requests manage
// everything. The control API under /api serves nobody else, so a KeeneticOS
// session never reads configuration, keys or journals there (ruling R14).
// Pages need a verified KeeneticOS session, and without that mode other peers
// are refused. Writes (methods other than GET and HEAD) need RoleManage.
func (s *Server) decide(r *http.Request) verdict {
	if isLoopback(r) {
		return verdict{role: RoleManage, status: http.StatusOK}
	}
	if s.Unavailable {
		return verdict{status: http.StatusServiceUnavailable, reason: "web interface unavailable; use an SSH tunnel to 127.0.0.1"}
	}
	if s.Keenetic == nil || isAPI(r.URL.Path) {
		return verdict{status: http.StatusForbidden, reason: "local access only"}
	}
	role, status := s.Keenetic.verify(r)
	if status == http.StatusOK && role != RoleManage && r.Method != http.MethodGet && r.Method != http.MethodHead {
		status = http.StatusForbidden
	}
	if status != http.StatusOK {
		status, reason := keeneticRefusal(status)
		return verdict{status: status, reason: reason}
	}
	return verdict{role: role, status: http.StatusOK}
}

// session reports whether the caller has access and, in KeeneticOS mode,
// where to sign in.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	authed := isLoopback(r)
	if s.Keenetic == nil {
		writeJSON(w, http.StatusOK, map[string]any{"authed": authed, "ip": clientIP(r)})
		return
	}
	if !authed {
		_, status := s.Keenetic.verify(r)
		authed = status == http.StatusOK
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authed":       authed,
		"ip":           clientIP(r),
		"keenetic_url": s.Keenetic.applicationsURL(),
	})
}

// logout ends the caller's KeeneticOS session. Trusted loopback has no router
// session here (an SSH tunnel carries no router cookie), so it is a no-op.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.Keenetic != nil && !isLoopback(r) {
		if status := s.Keenetic.logout(r); status != http.StatusOK {
			writeKeeneticError(w, status)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		daemon.Status
		Build buildIdentity `json:"build"`
	}{s.D.Status(r.Context()), runningBuild})
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.D.Config()
	if cfg == nil {
		writeError(w, http.StatusServiceUnavailable, "daemon is still starting")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// decodeConfig parses a size-bounded JSON configuration and applies model defaults.
func decodeConfig(r *http.Request) (*model.Config, error) {
	var cfg model.Config
	dec := json.NewDecoder(io.LimitReader(r.Body, maxConfigJSONBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	cfg.Defaults()
	return &cfg, nil
}

// validateConfig checks model and engine profile constraints without applying changes.
func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := decodeConfig(r)
	if err == nil {
		err = cfg.Validate()
	}
	if err == nil {
		err = validateEngineProfiles(r.Context(), cfg)
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// putConfig validates and applies the complete configuration through the daemon.
func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := decodeConfig(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration: "+err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	ctx = daemon.WithActor(ctx, daemon.Actor{Who: "user", From: clientIP(r)})
	if err := s.D.Apply(ctx, cfg); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.D.Config())
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	list := s.D.Devices()
	if list == nil {
		list = []daemon.Device{}
	}
	writeJSON(w, http.StatusOK, list)
}

// stats returns per-connection summaries, including history when series=1.
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.D.Stats(r.URL.Query().Get("series") == "1"))
}

// hosts returns the busiest hosts matching q and the match count before limit.
// A missing or out-of-range limit keeps the historical default of 200; the
// upper bound is the tracker's retention, so callers can request every host.
func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > stats.MaxHosts {
		limit = 200
	}
	list, total := s.D.Hosts(q.Get("tag"), q.Get("q"), limit)
	// Keep the JSON list contract independent of nil backend slices.
	if list == nil {
		list = []stats.Host{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": list, "total": total})
}

// parseLink returns connection-link metadata for the creation wizard.
func (s *Server) parseLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	link := strings.TrimSpace(req.Link)
	if strings.HasPrefix(link, "tt://") {
		outbound, err := trusttunnel.ParseOutbound(link)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		name := links.Name(link)
		if name == "" {
			if ep, err := trusttunnel.ParseLink(link); err == nil {
				name = ep.Name
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"type": model.ConnLink, "name": name, "protocol": "trusttunnel",
			"server": outbound["server"], "port": outbound["server_port"], "tls": outbound["tls"] != nil,
		})
		return
	}
	o, err := links.Parse(link)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"type": model.ConnLink, "name": links.Name(link), "protocol": o["type"],
		"server": o["server"], "port": o["server_port"], "tls": o["tls"] != nil, "transport": o["transport"],
	})
}

// rebuildingUI is a temporary placeholder for every non-API path; it goes away
// when the server-rendered UI lands.
func rebuildingUI(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "KeenProxy interface is being rebuilt", http.StatusServiceUnavailable)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
