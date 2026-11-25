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
			runner := newRecoveryTestFirewall()
			runner.cancel, runner.failRestore = cancel, tc.failRestore
			d, _ := startMemoryDaemon(t, path, runner, 768*memoryMiB)
			if tc.failRestore == 2 {
				// Model a firmware rebuild before the candidate and rollback fail.
				clear(runner.jumps)
				clear(runner.chains)
				runner.filterRules = ""
			}
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
				assertProtectedWatchdogRecovery(t, d, runner)
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

func assertProtectedWatchdogRecovery(t *testing.T, d *Daemon, runner *applyCancellationFirewall) {
	t.Helper()
	tcp := [3]string{"nat", "PREROUTING", netfilter.ChainTCP}
	dns := [3]string{"nat", "PREROUTING", netfilter.ChainDNS}
	forwardDrop := rollbackSourceDrop
	dropsDNS := func(hook string) bool {
		return runner.drops(hook, "-p tcp --dport 53"+newOriginalDrop) && runner.drops(hook, rollbackDNSDrop)
	}
	guarded := func() bool {
		return runner.drops("FORWARD", forwardDrop) && dropsDNS("INPUT") && dropsDNS("FORWARD")
	}
	if !guarded() || runner.jumps[tcp] || runner.jumps[dns] {
		t.Fatal("failed rollback did not leave an active drop guard and missing NAT jumps")
	}
	// Check the packet path at each command boundary, including a successful
	// chain restore followed by a failed DNS jump insertion or verification.
	gap := false
	runner.observe = func() {
		if (!runner.jumps[tcp] && !runner.drops("FORWARD", forwardDrop)) ||
			(!runner.jumps[dns] && (!dropsDNS("INPUT") || !dropsDNS("FORWARD"))) {
			gap = true
		}
	}
	defer func() { runner.observe = nil }()

	runner.fail = true // Allow the TCP insert and fail the following DNS insert.
	d.watch(t.Context())
	if gap || !guarded() || !runner.jumps[tcp] || runner.jumps[dns] || d.Status(t.Context()).Firewall {
		t.Fatal("watchdog lost rollback protection while the DNS entry jump could not be inserted")
	}

	runner.fail = false
	runner.loseDNSOnCheck = true
	d.watch(t.Context())
	if gap || !guarded() || runner.jumps[dns] || d.Status(t.Context()).Firewall {
		t.Fatal("watchdog lost rollback protection while the DNS entry jump could not be verified")
	}

	runner.loseDNSOnCheck = false
	runner.rebuildDuringRelease = true
	d.watch(t.Context())
	if runner.rebuildDuringRelease || gap || !guarded() || !runner.jumps[tcp] || runner.jumps[dns] || d.Status(t.Context()).Firewall {
		t.Fatal("guard release exposed traffic during a NAT rebuild and failed follow-up insertion")
	}
	runner.fail = false
	d.watch(t.Context())
	status := d.Status(t.Context())
	if gap || strings.Contains(runner.filterRules, "-j DROP") || !runner.jumps[tcp] || !runner.jumps[dns] || !status.Firewall || status.Restored != 1 {
		t.Fatal("watchdog did not restore interception and release the guard without a forwarding gap")
	}
}

func TestWatchdogRearmsFailedRollbackGuardWithOrdinaryHooks(t *testing.T) {
	runner := newRecoveryTestFirewall()
	d := startRollbackGuardFixture(t, runner)
	// A NAT-only rebuild leaves the ordinary filter jumps and rules intact.
	runner.removeNATJumps()
	runner.failRestore, runner.failGuardWrites = 2, 1
	if err := d.ApplyIfCurrent(t.Context(), d.Config(), model.ConfigRevision(d.Config())); !errors.Is(err, errApplyCancellationRestore) {
		t.Fatalf("expected the candidate and rollback firewall failure, got %v", err)
	}
	if runner.failGuardWrites != 0 || runner.drops("FORWARD", rollbackSourceDrop) ||
		!runner.jumps[[3]string{"filter", "FORWARD", netfilter.ChainQUIC}] {
		t.Fatal("test fixture did not leave ordinary filter hooks after the guard write failed")
	}
	runner.fail = true
	d.watch(t.Context())
	if d.Status(t.Context()).Firewall || !runner.drops("FORWARD", rollbackSourceDrop) ||
		!runner.drops("INPUT", rollbackDNSDrop) {
		t.Fatal("watchdog failed to re-arm rollback drops before another failed interception install")
	}
}

func TestFirewallMaintainsGuardWithoutReadyDependencies(t *testing.T) {
	runner := newRecoveryTestFirewall()
	d := startRollbackGuardFixture(t, runner)
	// Compilation cannot write its rule sets or reach the firewall install.
	d.opt.RuleSetDir = d.opt.ConfigPath
	cfg := d.Config()
	if err := d.ApplyIfCurrent(t.Context(), cfg, model.ConfigRevision(cfg)); err == nil {
		t.Fatal("apply unexpectedly reached firewall activation with an unusable rule-set directory")
	}
	if !runner.drops("FORWARD", rollbackSourceDrop) || !runner.drops("INPUT", rollbackDNSDrop) {
		t.Fatal("dependency failure did not arm the saved plan's filter guard")
	}
	for _, recover := range []struct {
		name string
		run  func(context.Context)
	}{
		{"watchdog", d.watch}, {"netfilter_hook", d.checkFirewallEvent},
	} {
		t.Run(recover.name, func(t *testing.T) {
			clear(runner.jumps)
			clear(runner.chains)
			runner.filterRules = ""
			recover.run(t.Context())
			status := d.Status(t.Context())
			if !runner.drops("FORWARD", rollbackSourceDrop) || !runner.drops("INPUT", rollbackDNSDrop) ||
				runner.jumps[[3]string{"nat", "PREROUTING", netfilter.ChainTCP}] ||
				runner.jumps[[3]string{"nat", "PREROUTING", netfilter.ChainDNS}] || status.Firewall || status.Restored != 0 {
				t.Fatal("recovery did not restore only the filter guard while interception dependencies were unavailable")
			}
		})
	}
}

func TestWatchdogClearsGuardAfterVerifiedRecovery(t *testing.T) {
	runner := newRecoveryTestFirewall()
	d := startRollbackGuardFixture(t, runner)
	runner.removeNATJumps()
	runner.failRestore = 2
	cfg := d.Config()
	if err := d.ApplyIfCurrent(t.Context(), cfg, model.ConfigRevision(cfg)); !errors.Is(err, errApplyCancellationRestore) {
		t.Fatalf("expected candidate and rollback restore failures, got %v", err)
	}
	runner.loseDNSAtGuardRemoval = true
	d.watch(t.Context())
	if status := d.Status(t.Context()); runner.loseDNSAtGuardRemoval || status.Firewall || status.Restored != 0 ||
		!runner.drops("INPUT", rollbackDNSDrop) {
		t.Fatal("a DNS jump loss during guard removal did not re-arm protection before retry")
	}
	runner.failDNSInsert = false
	d.watch(t.Context())
	if status := d.Status(t.Context()); !status.Firewall || status.Restored != 1 || strings.Contains(runner.filterRules, "-j DROP") {
		t.Fatal("verified recovery left temporary drops in the filter table")
	}
	if err := d.ApplyIfCurrent(t.Context(), cfg, model.ConfigRevision(cfg)); err != nil || strings.Contains(runner.filterRules, "-j DROP") {
		t.Fatalf("a later healthy install retained rollback drops: %v", err)
	}
}

func TestWatchdogGuardsAnOrdinaryDNSOnlyLoss(t *testing.T) {
	runner := newRecoveryTestFirewall()
	d := startRollbackGuardFixture(t, runner)
	dns := [3]string{"nat", "PREROUTING", netfilter.ChainDNS}
	delete(runner.jumps, dns)
	runner.failDNSInsert = true
	d.watch(t.Context())
	if runner.jumps[dns] || d.Status(t.Context()).Firewall || !runner.drops("INPUT", rollbackDNSDrop) {
		t.Fatal("ordinary DNS-only recovery did not guard new DNS while the jump was missing")
	}
	runner.failDNSInsert = false
	d.watch(t.Context())
	if status := d.Status(t.Context()); !status.Firewall || status.Restored != 1 || strings.Contains(runner.filterRules, "-j DROP") {
		t.Fatal("DNS-only recovery left temporary drops after verifying the restored jump")
	}
}

func newRecoveryTestFirewall() *applyCancellationFirewall {
	return &applyCancellationFirewall{recoveryFirewall: recoveryFirewall{
		jumps: make(map[[3]string]bool), chains: make(map[[2]string]bool),
	}}
}

func startRollbackGuardFixture(t *testing.T, runner netfilter.Runner) *Daemon {
	t.Helper()
	holdMemoryLimit(t)
	cfg := quietConfig(t)
	cfg.Connections = []model.Connection{{ID: "saved", Type: model.ConnLink, Link: "socks5://saved.example.test:1080"}}
	cfg.Networks = []model.Network{{CIDR: "192.0.2.0/24", Mode: model.ModeFull, Target: "saved"}}
	d := newMemoryDaemon(t, writeSavedConfig(t, cfg), runner)
	t.Cleanup(d.shutdown)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	return d
}

const (
	newOriginalDrop    = " -m conntrack --ctstate NEW --ctdir ORIGINAL -j DROP"
	rollbackSourceDrop = "-s 192.0.2.0/24 -p tcp" + newOriginalDrop
	rollbackDNSDrop    = "-p udp --dport 53" + newOriginalDrop
)

var errApplyCancellationRestore = errors.New("synthetic firewall restore failed")

type applyCancellationFirewall struct {
	recoveryFirewall
	cancel                context.CancelFunc
	failRestore           int
	failGuardWrites       int
	failDNSInsert         bool
	lastPlan, filterRules string
	loseDNSOnCheck        bool
	rebuildDuringRelease  bool
	loseDNSAtGuardRemoval bool
	observe               func()
}

func (r *applyCancellationFirewall) Run(ctx context.Context, input, name string, args ...string) error {
	if r.observe != nil {
		defer r.observe()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if name == "iptables-restore" && strings.HasPrefix(input, "*nat\n") {
		if r.attempts == 1 && r.cancel != nil {
			r.cancel()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.attempts > 0 && r.attempts <= r.failRestore {
			r.attempts++
			return errApplyCancellationRestore
		}
		r.lastPlan = input
	}
	if r.failGuardWrites != 0 && strings.Contains(input, rollbackSourceDrop) {
		r.failGuardWrites--
		return errApplyCancellationRestore
	}
	if r.loseDNSOnCheck && name == "iptables" && args[3] == "-C" && args[len(args)-1] == netfilter.ChainDNS {
		delete(r.jumps, [3]string{"nat", "PREROUTING", netfilter.ChainDNS})
	}
	if r.failDNSInsert && name == "iptables" && args[3] == "-I" && args[len(args)-1] == netfilter.ChainDNS {
		return errApplyCancellationRestore
	}
	if err := r.recoveryFirewall.Run(ctx, input, name, args...); err != nil {
		return err
	}
	if _, rules, found := strings.Cut(input, "*filter\n"); found {
		if r.loseDNSAtGuardRemoval && strings.Contains(r.filterRules, "-j DROP") && !strings.Contains(rules, "-j DROP") {
			r.loseDNSAtGuardRemoval = false
			delete(r.jumps, [3]string{"nat", "PREROUTING", netfilter.ChainDNS})
			r.failDNSInsert = true
		}
		r.filterRules = rules
		if r.rebuildDuringRelease && r.jumps[[3]string{"nat", "PREROUTING", netfilter.ChainTCP}] &&
			r.jumps[[3]string{"nat", "PREROUTING", netfilter.ChainDNS}] && strings.Contains(rules, rollbackSourceDrop) {
			r.rebuildDuringRelease = false
			r.removeNATJumps()
			r.fail = true // The follow-up restore can add TCP, but fails to add DNS.
		}
	}
	return nil
}

func (r *applyCancellationFirewall) removeNATJumps() {
	delete(r.jumps, [3]string{"nat", "PREROUTING", netfilter.ChainTCP})
	delete(r.jumps, [3]string{"nat", "PREROUTING", netfilter.ChainDNS})
}

func (r *applyCancellationFirewall) drops(hook, ruleSuffix string) bool {
	for line := range strings.SplitSeq(r.filterRules, "\n") {
		rule, isRule := strings.CutPrefix(line, "-A ")
		if isRule && strings.HasSuffix(rule, ruleSuffix) {
			chain, _, _ := strings.Cut(rule, " ")
			if r.jumps[[3]string{"filter", hook, chain}] {
				return true
			}
		}
	}
	return false
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
