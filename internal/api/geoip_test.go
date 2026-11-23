package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
)

// geoFake serves one enabled database, "dbip", that maps every address to RU.
type geoFake struct{ *fakeDaemon }

func (g geoFake) GeoDatabases() []daemon.GeoDatabaseInfo {
	out := make([]daemon.GeoDatabaseInfo, len(g.cfg.GeoIP.Databases))
	for i, db := range g.cfg.GeoIP.Databases {
		out[i] = daemon.GeoDatabaseInfo{ID: db.ID}
	}
	return out
}
func (geoFake) UpdateGeo(context.Context, string) error { return nil }
func (geoFake) LookupGeo(_ netip.Addr, id string) (daemon.GeoLookup, error) {
	if id != "" {
		return daemon.GeoLookup{}, errors.New("unknown database")
	}
	return daemon.GeoLookup{Country: "RU", Database: "dbip", Results: make([]daemon.GeoLookupResult, 1)}, nil
}

func TestGeoEndpoints(t *testing.T) {
	s, fake := newServer()
	cfg := fake.cfg
	s.D = geoFake{fake}
	h := s.Handler()
	if w := do(t, h, "POST", "/api/geoip/lookup", `{"ip":"77.88.8.8"}`, "", lan); w.Code != 401 {
		t.Fatal("authorization required", w.Code)
	}
	for _, body := range []string{`{"ip":"example.com"}`, `{"ip":"fe80::1%eth0"}`, `{"ip":"1.1.1.1","extra":1}`} {
		if w := do(t, h, "POST", "/api/geoip/lookup", body, "secret", lan); w.Code != 400 {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	w := do(t, h, "POST", "/api/geoip/lookup", `{"ip":"77.88.8.8"}`, "secret", lan)
	var res daemon.GeoLookup
	json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || res.Country != "RU" || res.Database != "dbip" || len(res.Results) != 1 {
		t.Fatalf("enabled: %d %s", w.Code, w.Body)
	}
	if w := do(t, h, "POST", "/api/geoip/lookup", `{"ip":"77.88.8.8","id":"nope"}`, "secret", lan); w.Code != 400 {
		t.Fatalf("unknown database: %d", w.Code)
	}
	w = do(t, h, "GET", "/api/geoip", "", "secret", lan)
	var list geoResponse
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Databases) != len(cfg.GeoIP.Databases) {
		t.Fatalf("list: %s", w.Body)
	}
	w = do(t, h, "GET", "/api/catalog", "", "secret", lan)
	if !strings.Contains(w.Body.String(), `"geoip":[{"id":"dbip"`) {
		t.Fatalf("catalog: %s", w.Body)
	}
}
