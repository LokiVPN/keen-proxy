package daemon

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestApplyRestoresPreviousCoreOnStartFailure(t *testing.T) {
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.System.MemoryLimitMiB = new(model.MemoryLimitMiB(400))
	cfg.Connections = []model.Connection{{ID: "saved", Type: model.ConnLink, Link: "socks5://saved.example.test:1080"}}
	path := writeSavedConfig(t, cfg)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := startMemoryDaemon(t, path, &gateRunner{}, 400*memoryMiB)
	_, originalCore, ok := d.eng.Outbound("saved")
	if !ok {
		t.Fatal("saved core was not running")
	}
	revision := model.ConfigRevision(d.Config())
	candidate := d.Config()
	candidate.Connections[0] = model.Connection{ID: "candidate", Type: model.ConnSingBox, Endpoint: map[string]any{
		"type": "wireguard", "address": []string{"10.1.0.2/32"},
		"private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "detour": model.TargetDirect,
		"peers": []map[string]any{{
			"address": "192.0.2.10", "port": 51820, "allowed_ips": []string{"0.0.0.0/0"},
			"public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		}},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = d.ApplyIfCurrent(ctx, candidate, revision)
	if err == nil || !strings.Contains(err.Error(), "start sing-box") ||
		!strings.Contains(err.Error(), "detour to an empty direct outbound") {
		t.Fatalf("expected Start to reject the WireGuard detour, got %v", err)
	}
	_, restoredCore, ok := d.eng.Outbound("saved")
	if !ok || originalCore.Err() == nil || restoredCore.Err() != nil || !d.eng.Running() {
		t.Fatal("the failed Start did not leave a running replacement of the saved core")
	}
	if _, _, found := d.eng.Outbound("candidate"); found || model.ConfigRevision(d.Config()) != revision {
		t.Fatal("the failed candidate remained active")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("the failed candidate reached the saved configuration file")
	}
}
