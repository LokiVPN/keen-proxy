package api

import (
	"net"
	"net/http"
	"slices"
	"strconv"

	"github.com/ordo-systems/keen-proxy/internal/journal"
)

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) journalOf(w http.ResponseWriter, r *http.Request) (journal.Kind, *journal.Journal, bool) {
	k := journal.Kind(r.PathValue("kind"))
	if !slices.Contains(journal.Kinds, k) {
		writeError(w, http.StatusNotFound, "unknown journal")
		return "", nil, false
	}
	j := s.D.Journal(k)
	if j == nil {
		writeError(w, http.StatusServiceUnavailable, "journal unavailable")
		return "", nil, false
	}
	return k, j, true
}

// journalPage returns newest-first entries with q, before, limit, and
// field-name filters such as outbound or level.
func (s *Server) journalPage(w http.ResponseWriter, r *http.Request) {
	k, j, ok := s.journalOf(w, r)
	if !ok {
		return
	}
	v := r.URL.Query()
	q := journal.Query{Text: v.Get("q"), Filters: map[string]string{}}
	q.Before, _ = strconv.ParseUint(v.Get("before"), 10, 64)
	q.Limit, _ = strconv.Atoi(v.Get("limit"))
	for _, f := range journal.Fields[k] {
		if x := v.Get(f); x != "" {
			q.Filters[f] = x
		}
	}
	writeJSON(w, http.StatusOK, j.Find(q, journal.Fields[k]))
}
