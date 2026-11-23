package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
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

func TestDerivedOriginFailureKeepsLoopbackPanel(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		cfg := &model.Config{API: model.API{Listen: addr}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		listening := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- serveAPI(ctx, cfg, statusDaemon{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)),
				"http://192.168.1.1", explicit, false, func(context.Context) { close(listening) })
		}()
		if explicit {
			if err := <-done; err == nil {
				t.Error("an explicit origin that cannot work must fail loudly")
			}
			cancel()
			continue
		}
		<-listening
		if c := get(t, addr, addr); c != http.StatusOK {
			t.Errorf("loopback: %d, want 200", c)
		}
		if c := get(t, addr, "192.168.1.1:8086"); c != http.StatusServiceUnavailable {
			t.Errorf("foreign Host: %d, want 503", c)
		}
		cancel()
		<-done
	}
}
