package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

func TestSupportExportsKeepActivationMetadataPrivate(t *testing.T) {
	const private = "private-disabled-activation.example"
	const historical = "historical-disabled-activation.example"
	s, fake := newServer()
	fake.cfg.Groups = []model.Group{{
		Name: "rules", Target: model.TargetDirect,
		Entries: []string{private}, DisabledEntries: []string{private, historical},
		Preset: &model.Preset{ID: "saved", Base: []string{private}},
	}}
	raw, err := json.Marshal(supportConfig(fake.cfg, func(kind, value string) string { return kind + "-alias" }))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), private) || strings.Contains(string(raw), historical) {
		t.Fatal("anonymous support projection leaked inactive metadata")
	}
	w := do(t, s.Handler(), "GET", "/api/config/yaml?redacted=1", "", "secret", lan)
	if w.Code != 200 || strings.Contains(w.Body.String(), historical) || strings.Contains(w.Body.String(), "disabled_entries") {
		t.Fatalf("redacted YAML leaked historical activation metadata: %s", w.Body)
	}
	if !strings.Contains(w.Body.String(), private) {
		t.Fatal("credential redaction unexpectedly removed existing policy data")
	}
	w = do(t, s.Handler(), "GET", "/api/config/yaml", "", "secret", lan)
	if w.Code != 200 || !strings.Contains(w.Body.String(), private) || !strings.Contains(w.Body.String(), historical) {
		t.Fatal("restorable backup lost inactive metadata")
	}
}

// emptyHostsDaemon reports no matching hosts.
type emptyHostsDaemon struct{ *fakeDaemon }

func (emptyHostsDaemon) Hosts(_, _ string, _ int) ([]stats.Host, int) { return nil, 0 }

func TestEmptyHostsResponseIsArray(t *testing.T) {
	s, fake := newServer()
	s.D = emptyHostsDaemon{fake}
	for _, path := range []string{"/api/stats/hosts?tag=off", "/api/stats/hosts?tag=on&q=missing.invalid"} {
		t.Run(path, func(t *testing.T) {
			w := do(t, s.Handler(), "GET", path, "", "secret", lan)
			var response struct {
				Hosts json.RawMessage `json:"hosts"`
				Total int             `json:"total"`
			}
			if w.Code != 200 {
				t.Fatalf("hosts status = %d: %s", w.Code, w.Body)
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if string(response.Hosts) != "[]" || response.Total != 0 {
				t.Fatalf("empty host list must render as an array: %s", w.Body)
			}
		})
	}
}
