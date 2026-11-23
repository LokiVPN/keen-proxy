package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/api"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

type statusDaemon struct{ api.Daemon }

func (statusDaemon) Status(context.Context) daemon.Status { return daemon.Status{} }

// get requests the panel with a chosen Host; non-loopback peers cannot be
// simulated over a real socket, so the loopback peer proves the 200 and the
// 503 for a foreign Host proves the unavailable mode.
func get(t *testing.T, addr, host string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+addr+"/api/status", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// An origin that cannot work, derived or set by the operator, must not take
// the loopback panel down with it (ruling R16): browsers get 503, loopback
// keeps working, and the reason is logged as an error.
func TestFailedOriginKeepsLoopbackPanel(t *testing.T) {
	for _, operator := range []bool{false, true} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		cfg := &model.Config{API: model.API{Listen: addr}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var logs bytes.Buffer
		listening := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- serveAPI(ctx, cfg, statusDaemon{}, nil, slog.New(slog.NewTextHandler(&logs, nil)),
				"http://192.168.1.1", operator, false, func(context.Context) { close(listening) })
		}()
		select {
		case <-listening:
		case err := <-done:
			cancel()
			t.Fatalf("operator origin %t: serveAPI stopped before listening: %v", operator, err)
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatalf("operator origin %t: serveAPI did not start listening", operator)
		}
		if c := get(t, addr, addr); c != http.StatusOK {
			t.Errorf("operator origin %t: loopback: %d, want 200", operator, c)
		}
		if c := get(t, addr, "192.168.1.1:8086"); c != http.StatusServiceUnavailable {
			t.Errorf("operator origin %t: foreign Host: %d, want 503", operator, c)
		}
		if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "sign-in unavailable") {
			t.Errorf("operator origin %t: log = %q", operator, logs.String())
		}
		cancel()
		<-done
	}
}

// With keeneticOrigin already failed in main, serveAPI must not log a second
// "sign-in unavailable" line.
func TestUnavailableModeLogsNothingInServeAPI(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveAPI(ctx, &model.Config{API: model.API{Listen: addr}}, statusDaemon{}, nil,
			slog.New(slog.NewTextHandler(&buf, nil)), "", false, true, func(context.Context) { close(listening) })
	}()
	select {
	case <-listening:
	case err := <-done:
		t.Fatalf("serveAPI stopped before listening: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("serveAPI did not start listening")
	}
	cancel()
	<-done
	if bytes.Contains(buf.Bytes(), []byte("sign-in unavailable")) {
		t.Errorf("duplicate log line: %s", buf.String())
	}
}
