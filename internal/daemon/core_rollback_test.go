package daemon

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

func TestAdmittedApplySurvivesRequestCancellation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failRestore int
	}{
		{name: "commit"},
		{name: "rollback", failRestore: 1},
		{name: "failed rollback stays protected", failRestore: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holdMemoryLimit(t)
			cfg := quietConfig(t)
			cfg.Connections = []model.Connection{{ID: "saved", Type: model.ConnLink, Link: "socks5://saved.example.test:1080"}}
			cfg.Networks = []model.Network{{CIDR: "192.0.2.0/24", Mode: model.ModeFull, Target: "saved"}}
			cfg.DNS.BypassSources = []string{"192.0.2.53"}
			path := writeSavedConfig(t, cfg)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/devices", nil)
			runner := &applyCancellationFirewall{
				recoveryFirewall: recoveryFirewall{jumps: make(map[[3]string]bool), chains: make(map[[2]string]bool)},
				cancel:           cancel,
				failRestore:      tc.failRestore,
			}
			d, _ := startMemoryDaemon(t, path, runner, 768*memoryMiB)
			current := d.Config()
			revision := model.ConfigRevision(current)
			candidate := current.Clone()
			candidate.Connections[0].Link = "socks5://changed.example.test:1080"
			candidate.DNS.BypassSources = []string{"192.0.2.54"}
			err := d.ApplyIfCurrent(request.Context(), candidate, revision)
			if ctx.Err() != context.Canceled {
				t.Fatal("request was not canceled during candidate firewall installation")
			}
			wantBypass := "192.0.2.54"
			if tc.failRestore != 0 {
				wantBypass = "192.0.2.53"
				if !errors.Is(err, errApplyCancellationRestore) || model.ConfigRevision(d.Config()) != revision {
					t.Fatalf("canceled request prevented rollback: %v", err)
				}
			} else if err != nil {
				t.Fatalf("canceled request interrupted admitted Apply: %v", err)
			}
			saved, err := model.Load(path)
			if err != nil || saved.DNS.BypassSources[0] != wantBypass || d.Config().DNS.BypassSources[0] != wantBypass {
				t.Fatalf("running and saved configuration diverged: %v", err)
			}
			if tc.failRestore == 2 {
				if !strings.Contains(runner.protection, "-s 192.0.2.0/24 -j DROP") ||
					!strings.Contains(runner.protection, "--dport 53 -j DROP") ||
					!runner.jumps[[3]string{"filter", "FORWARD", netfilter.ChainQUIC}] ||
					!runner.jumps[[3]string{"filter", "INPUT", netfilter.ChainDNSGuard}] {
					t.Fatal("failed rollback left previously protected traffic or DNS unguarded")
				}
				return
			}
			status := d.Status(t.Context())
			if !status.Firewall || !status.CoreRunning || status.DNS == "" ||
				!strings.Contains(runner.lastPlan, "-s "+wantBypass+"/32") ||
				!runner.jumps[[3]string{"nat", "PREROUTING", netfilter.ChainTCP}] ||
				!runner.jumps[[3]string{"nat", "PREROUTING", netfilter.ChainDNS}] {
				t.Fatal("apply left the expected TCP or DNS interception inactive")
			}
		})
	}
}

var errApplyCancellationRestore = errors.New("synthetic firewall restore failed")

type applyCancellationFirewall struct {
	recoveryFirewall
	cancel               context.CancelFunc
	failRestore          int
	lastPlan, protection string
}

func (r *applyCancellationFirewall) Run(ctx context.Context, input, name string, args ...string) error {
	if name == "iptables-restore" {
		if r.attempts == 1 {
			r.cancel()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if strings.HasPrefix(input, "*filter\n") {
			r.protection = input
		} else if r.attempts > 0 && r.attempts <= r.failRestore {
			r.attempts++
			return errApplyCancellationRestore
		} else {
			r.lastPlan = input
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.recoveryFirewall.Run(ctx, input, name, args...)
}

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
	initialStatus := d.Status(t.Context())
	if !initialStatus.CoreRunning || initialStatus.AppliedAt.IsZero() {
		t.Fatal("startup did not publish core state and configuration apply time")
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
	if st := d.Status(ctx); !st.CoreRunning || !st.AppliedAt.Equal(initialStatus.AppliedAt) {
		t.Fatal("a failed apply changed the last successful configuration time")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("the failed candidate reached the saved configuration file")
	}
}
