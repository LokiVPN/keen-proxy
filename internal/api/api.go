// Package api serves the keenProxy HTTP API and web interface.
//
// The HTTP API is a control API for local processes: it trusts only loopback
// peers, judged by RemoteAddr alone. Other peers reach it only through a
// verified KeeneticOS session when that sign-in mode is enabled. A separate
// address guard restricts access to private, loopback, and link-local peers
// even when the listening port is exposed.
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
	"github.com/ordo-systems/keen-proxy/internal/resourceexchange"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/trusttunnel"
	"github.com/ordo-systems/keen-proxy/internal/update"
)

const maxConfigJSONBytes = 8 << 20

// Daemon defines the daemon capabilities used by the API and its test doubles.
type Daemon interface {
	Domains() daemon.DomainStatus
	RefreshDomains(context.Context, []string, bool) (daemon.DomainStatus, error)
	Config() *model.Config
	Apply(ctx context.Context, cfg *model.Config) error
	Status(ctx context.Context) daemon.Status
	Devices() []daemon.Device
	Stats(withSeries bool) stats.Snapshot
	Hosts(tag, query string, limit int) ([]stats.Host, int)
	Journal(kind journal.Kind) *journal.Journal
	// Mask redacts configuration secrets from exported journal text.
	Mask() func(string) string
}

// Server binds daemon operations and authentication policy.
type Server struct {
	D        Daemon
	Log      *slog.Logger
	Updates  *update.Manager
	Keenetic *KeeneticAuth

	supportBusy  atomic.Bool
	resourceBusy atomic.Bool
}

// Handler builds the API routes and applies the peer-address guard to all requests.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /api/diagnostics/check", s.auth(s.diagnosticCheck))
	mux.Handle("GET /api/diagnostics/bundle", s.auth(s.supportBundle))
	mux.Handle("GET /api/diagnostics/tproxy", s.auth(s.tproxyReadiness))
	mux.Handle("POST /api/diagnostics/tproxy/retry", s.auth(s.retryTProxy))
	mux.Handle("GET /api/catalog", s.auth(s.catalog))
	mux.Handle("GET /api/features", s.auth(s.features))
	mux.Handle("POST /api/presets/preview", s.auth(s.presetPreview))
	mux.Handle("POST /api/resources/preview", s.resourceExchange("application/octet-stream", resourceexchange.MaxFileBytes, previewResources))
	mux.Handle("POST /api/resources/export", s.resourceExchange("application/json", maxResourceExportBytes, exportResources))
	mux.Handle("GET /api/subscriptions/status", s.auth(s.subscriptionStatus))
	mux.Handle("POST /api/subscriptions/preview", s.auth(s.subscriptionPreview))
	mux.Handle("POST /api/subscriptions/{id}/refresh", s.auth(s.subscriptionRefresh))
	mux.Handle("POST /api/subscriptions/{id}/check", s.auth(s.subscriptionCheck))
	mux.Handle("POST /api/filters/refresh", s.auth(s.refreshFilters))
	mux.Handle("POST /api/dns/check", s.auth(s.checkDNS))
	mux.Handle("GET /api/geoip", s.auth(s.geoDatabases))
	mux.Handle("POST /api/geoip/update", s.auth(s.updateGeo))
	mux.Handle("POST /api/geoip/lookup", s.auth(s.lookupGeo))
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/session", s.session)
	mux.Handle("GET /api/domains", s.auth(s.domainStatus))
	mux.Handle("POST /api/domains/resolve", s.auth(s.resolveDomains))
	mux.Handle("GET /api/status", s.auth(s.status))
	mux.Handle("GET /api/config", s.auth(s.getConfig))
	mux.Handle("GET /api/config/yaml", s.auth(s.yamlExport))
	mux.Handle("POST /api/config/import", s.auth(s.yamlImport))
	mux.Handle("GET /api/config/previous", s.auth(s.previousConfig))
	mux.Handle("PUT /api/config", s.auth(s.putConfig))
	mux.Handle("POST /api/config/validate", s.auth(s.validateConfig))
	mux.Handle("GET /api/devices", s.auth(s.devices))
	mux.Handle("POST /api/links/parse", s.auth(s.parseLink))
	mux.Handle("POST /api/amnezia/import", s.auth(s.amneziaImport))
	mux.Handle("GET /api/stats", s.auth(s.stats))
	mux.Handle("GET /api/stats/hosts", s.auth(s.hosts))
	mux.Handle("GET /api/journal/{kind}", s.auth(s.journalPage))
	mux.Handle("GET /api/journal/{kind}/stream", s.auth(s.journalStream))
	mux.Handle("GET /api/journal/{kind}/export", s.auth(s.journalExport))
	s.updateRoutes(mux)
	mux.Handle("/api/", http.NotFoundHandler())
	mux.HandleFunc("/", rebuildingUI)
	return s.lanOnly(mux)
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

// isLoopback reports whether the peer is a local process. It uses only
// RemoteAddr; client-controlled forwarding headers are untrusted.
func isLoopback(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// authorized applies the access policy: loopback peers are trusted, other
// peers need a verified KeeneticOS session, and without that mode they are
// refused. It writes the refusal itself.
func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case isLoopback(r):
		return true
	case s.Keenetic != nil:
		return s.allowKeenetic(w, r)
	default:
		writeError(w, http.StatusForbidden, "local access only")
		return false
	}
}

// auth applies the access policy before calling the endpoint.
func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authorized(w, r) {
			h(w, r)
		}
	})
}

// session reports whether the caller has access and, in KeeneticOS mode,
// where to sign in.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	if s.Keenetic != nil {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{
			"authed":       s.keeneticStatus(r) == http.StatusOK,
			"ip":           clientIP(r),
			"keenetic_url": s.Keenetic.applicationsURL(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authed": isLoopback(r), "ip": clientIP(r)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.Keenetic != nil {
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

// rebuildingUI answers every non-API path until the server-rendered UI exists.
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
