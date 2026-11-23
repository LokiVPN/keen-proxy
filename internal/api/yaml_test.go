package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestYAMLPreviewAndExport(t *testing.T) {
	s, d := newServer()
	h := s.Handler()
	if w := do(t, h, "GET", "/api/config/yaml", "", "", lan); w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
	w := do(t, h, "POST", "/api/config/import", `{"yaml":"{}"}`, "secret", local)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if d.applied != nil {
		t.Fatal("preview applied")
	}
	var c map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c["schema_version"] != float64(1) {
		t.Fatal(c)
	}
	w = do(t, h, "POST", "/api/config/import", `{"yaml":"{}\n---\n{}"}`, "secret", local)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	w = do(t, h, "GET", "/api/config/yaml", "", "secret", local)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w.Header().Get("Content-Disposition") == "" {
		t.Fatal("missing download header")
	}
}

func TestDNSBypassSourcesApplyAndExport(t *testing.T) {
	s, d := newServer()
	h := s.Handler()
	const resolver = "192.168.37.53"
	preview := do(t, h, "POST", "/api/config/import", `{"yaml":"dns: {bypass_sources: [`+resolver+`]}"}`, "secret", local)
	if preview.Code != http.StatusOK || d.applied != nil || !strings.Contains(preview.Body.String(), `"bypass_sources":["`+resolver+`"]`) {
		t.Fatalf("preview: %d %s, applied=%v", preview.Code, preview.Body, d.applied != nil)
	}
	applied := do(t, h, "PUT", "/api/config", preview.Body.String(), "secret", local)
	if applied.Code != http.StatusOK || !strings.Contains(applied.Body.String(), `"bypass_sources":["`+resolver+`"]`) {
		t.Fatalf("apply: %d %s", applied.Code, applied.Body)
	}
	bad := do(t, h, "PUT", "/api/config", `{"dns":{"bypass_sources":["192.168.37.0/24"]}}`, "secret", local)
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), "dns.bypass_sources[0]") {
		t.Fatalf("invalid apply: %d %s", bad.Code, bad.Body)
	}
	redacted := do(t, h, "GET", "/api/config/yaml?redacted=1", "", "secret", local)
	if redacted.Code != http.StatusOK || strings.Contains(redacted.Body.String(), resolver) {
		t.Fatalf("redacted export: %d %s", redacted.Code, redacted.Body)
	}
	full := do(t, h, "GET", "/api/config/yaml", "", "secret", local)
	if full.Code != http.StatusOK {
		t.Fatalf("backup: %d %s", full.Code, full.Body)
	}
	cfg, err := model.Parse(full.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.DNS.BypassSources; len(got) != 1 || got[0] != resolver {
		t.Fatalf("bypass sources in backup = %v", got)
	}
	cleared := do(t, h, "PUT", "/api/config", `{"dns":{"bypass_sources":[]}}`, "secret", local)
	if cleared.Code != http.StatusOK || strings.Contains(cleared.Body.String(), "bypass_sources") {
		t.Fatalf("clear: %d %s", cleared.Code, cleared.Body)
	}
}

func TestSupportExportRemovesURLSecrets(t *testing.T) {
	s, d := newServer()
	d.cfg.DNS.Upstreams = []string{"https://dns.example/private-token"}
	d.cfg.GeoIP.Databases = []model.GeoIPDatabase{{ID: "custom-1", URL: "https://geo.example/geo-token", Enabled: true}}
	d.cfg.Failover.URL = "https://health.example/health-token"
	w := do(t, s.Handler(), "GET", "/api/config/yaml?redacted=1", "", "secret", local)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, v := range []string{"private-token", "geo-token", "health-token"} {
		if strings.Contains(w.Body.String(), v) {
			t.Fatal("secret leaked", v)
		}
	}
}

func TestRedactedYAMLOmitsAmneziaWGSecrets(t *testing.T) {
	s, d := newServer()
	const (
		privateKey = "AWG-PRIVATE-7f3a9c1e-not-a-wireguard-key"
		psk        = "AWG-PSK-91ab44d0-not-a-wireguard-key"
		hpk        = "AWG-HPK-c0ffee12-not-a-wireguard-key"
		endpoint   = "awg-endpoint-203-0-113-44.example:51820"
	)
	profile := "[Interface]\nPrivateKey = " + privateKey + "\nHeaderProtectionKey = " + hpk + "\n[Peer]\nPresharedKey = " + psk + "\nEndpoint = " + endpoint + "\n"
	d.cfg.Connections = []model.Connection{{ID: "awg", Type: model.ConnAmneziaWG, AmneziaWG: profile}}
	h := s.Handler()
	plain := do(t, h, "GET", "/api/config/yaml", "", "secret", local)
	if plain.Code != 200 {
		t.Fatal(plain.Code, plain.Body.String())
	}
	for _, secret := range []string{privateKey, psk, hpk, endpoint} {
		if !strings.Contains(plain.Body.String(), secret) {
			t.Fatalf("fixture did not retain %s", secret)
		}
	}
	w := do(t, h, "GET", "/api/config/yaml?redacted=1", "", "secret", local)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, secret := range []string{privateKey, psk, hpk, endpoint} {
		if strings.Contains(body, secret) {
			t.Fatalf("redacted YAML leaked %s", secret)
		}
	}
	if !strings.Contains(body, "redacted: true") || !strings.Contains(body, "type: amneziawg") {
		t.Fatalf("redacted export lost connection identity: %s", body)
	}
	if d.cfg.Connections[0].AmneziaWG != profile {
		t.Fatal("export mutated the live profile")
	}
}

func TestYAMLRawImportBodyLimit(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	r := yamlImportRequest(strings.NewReader(strings.Repeat(" ", (3<<20)+1)), "secret")
	r.ContentLength = -1 // enforce the reader limit even without a declared length
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized raw YAML: %d %s", w.Code, w.Body)
	}
	unread := &resourceUnreadBody{}
	r = yamlImportRequest(unread, "secret")
	r.ContentLength = (3 << 20) + 1
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || unread.read {
		t.Fatalf("oversized declared YAML: %d read=%t", w.Code, unread.read)
	}
}

func TestYAMLImportSerializesBeforeReading(t *testing.T) {
	s, _ := newServer()
	h := s.Handler()
	started, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(unblock)
	body := &resourcePausedReader{Reader: strings.NewReader("{}"), started: started, resume: resume}
	done := startResourceRequest(h, yamlImportRequest(body, "secret"))
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("YAML import did not start reading")
	}
	for _, tc := range []struct{ path, media string }{
		{"/api/config/import", "application/yaml"},
		{"/api/config/import", "application/json"},
	} {
		unread := &resourceUnreadBody{}
		r := httptest.NewRequest(http.MethodPost, tc.path, unread)
		r.RemoteAddr = local
		r.Header.Set("Content-Type", tc.media)
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || unread.read || w.Header().Get("Connection") != "close" {
			t.Fatalf("competing %s (%s): %d read=%t %v %s", tc.path, tc.media, w.Code, unread.read, w.Header(), w.Body)
		}
	}
	unblock()
	select {
	case w := <-done:
		if w.Code != http.StatusOK {
			t.Fatalf("active YAML import: %d %s", w.Code, w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("active YAML import did not finish")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, yamlImportRequest(strings.NewReader("{}"), "secret"))
	if w.Code != http.StatusOK {
		t.Fatalf("YAML import did not release gate: %d %s", w.Code, w.Body)
	}
}

func yamlImportRequest(body io.Reader, token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/config/import", body)
	r.RemoteAddr = local
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/yaml; charset=utf-8")
	return r
}

type resourceUnreadBody struct{ read bool }

func (b *resourceUnreadBody) Read([]byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

// resourcePausedReader blocks its first read so a request holds the import gate.
type resourcePausedReader struct {
	io.Reader
	started chan struct{}
	resume  <-chan struct{}
}

func (p *resourcePausedReader) Read(dst []byte) (int, error) {
	if p.started != nil {
		close(p.started)
		p.started = nil
		<-p.resume
	}
	return p.Reader.Read(dst)
}

func startResourceRequest(h http.Handler, r *http.Request) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		done <- w
	}()
	return done
}
