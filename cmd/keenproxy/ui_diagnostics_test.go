package main

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/api"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

type diagnosticsArchiveDaemon struct {
	statusDaemon
	cfg    *model.Config
	system *journal.Journal
}

func (d diagnosticsArchiveDaemon) Config() *model.Config { return d.cfg }

func (d diagnosticsArchiveDaemon) Journal(kind journal.Kind) *journal.Journal {
	if kind == journal.System {
		return d.system
	}
	return nil
}

func TestDiagnosticsDownloadsRedactedSupportBundle(t *testing.T) {
	const source = "https://provider.example.test/private-subscription"
	const hwid = "synthetic-profile-hwid"
	system := journal.New(journal.Options{Memory: 3})
	t.Cleanup(system.Close)
	system.Add(journal.Entry{Source: "keenproxy", Level: "WARN", Message: "subscription check failed for " + source + " HWID " + hwid})
	d := diagnosticsArchiveDaemon{cfg: &model.Config{
		Subscriptions: []subscription.Source{{ID: "test-source", URL: source, SendHWID: true}},
	}, system: system}
	opts := ui.Options{Role: pageRole}
	server := &api.Server{D: d, PageError: opts.AccessError}
	server.Pages = ui.New(uiDeps{daemon: d, bundle: server.ServeSupportBundle}, opts)
	h := server.Handler()

	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8086/diagnostics/bundle.zip", nil)
	r.RemoteAddr = "127.0.0.1:8087"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/zip" ||
		w.Header().Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(w.Header().Get("Content-Disposition"), `attachment; filename="keenproxy-diagnostics-`) {
		t.Fatalf("diagnostic download HTTP %d, headers %v", w.Code, w.Header())
	}
	archive, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var config, status, systemLog bool
	for _, member := range archive.File {
		switch member.Name {
		case "config.json":
			config = true
		case "status.json":
			status = true
		case "journals/system.jsonl":
			systemLog = true
		}
		reader, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"provider.example.test", hwid, "test-source"} {
			if bytes.Contains(body, []byte(private)) {
				t.Errorf("private fixture data in %s", member.Name)
			}
		}
	}
	if !config || !status || !systemLog {
		t.Fatal("download did not include the existing support archive members")
	}
}

func TestDiagnosticsPostsRetainCentralOriginGuard(t *testing.T) {
	opts := ui.Options{Role: pageRole}
	server := &api.Server{Pages: ui.New(uiDeps{}, opts), PageError: opts.AccessError}
	h := server.Handler()
	for _, path := range []string{"/diagnostics/check", "/updates/check", "/updates/install", "/updates/rollback", "/updates/preferences"} {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8086"+path, nil)
		r.RemoteAddr = "127.0.0.1:8087"
		r.Header.Set("Origin", "https://foreign.example.test")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Access denied") {
			t.Errorf("foreign-origin POST %s returned HTTP %d, want HTML 403", path, w.Code)
		}
	}
}
