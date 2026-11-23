package api

import (
	"context"
	"net/http"
	"reflect"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// checkDNS validates draft DNS settings but requires referenced connection profiles to be applied.
func (s *Server) checkDNS(w http.ResponseWriter, r *http.Request) {
	var c model.Config
	if err := decodeJSONRequest(w, r, maxConfigJSONBytes, &c); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	d, ok := s.D.(interface {
		CheckDNS(context.Context, *model.Config) (daemon.DNSCheck, error)
	})
	if !ok {
		writeError(w, 501, "DNS check is unavailable")
		return
	}
	// Connection profiles in a draft are not running yet. Avoid testing another
	// live profile with the same id while presenting the draft as verified.
	if c.DNS.Route == "connection" {
		live := s.D.Config()
		if !reflect.DeepEqual(c.Connections, live.Connections) {
			writeError(w, 400, "Apply connection changes first")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := d.CheckDNS(ctx, &c)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
