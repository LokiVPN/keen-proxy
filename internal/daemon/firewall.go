package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
)

const firewallVerifyRetryDelay = 250 * time.Millisecond

// setFirewallPlan carries the guarded filter through config and neighbor
// recompiles after a guarded recovery in this daemon run.
func (d *Daemon) setFirewallPlan(plan netfilter.Plan) {
	plan.GuardUnintercepted = d.plan.GuardUnintercepted
	d.plan = plan
}

// installFirewall installs a plan during Apply or a neighbor update. Guarded
// installs always verify their handoff before reporting success.
func (d *Daemon) installFirewall(ctx context.Context) error {
	after, err := d.applyFirewall(ctx, false)
	if after != nil {
		return errors.Join(fmt.Errorf("verify guarded interception: %s", after.Error), err)
	}
	return err
}

// applyFirewall keeps the guard plan until final verification succeeds. A
// failed install stays pending even when residual entry jumps pass checks.
func (d *Daemon) applyFirewall(ctx context.Context, verify bool) (*netfilter.CheckFailure, error) {
	f := d.opt.Firewall
	guarded := d.planGuard != nil
	var err error
	if !guarded {
		err = f.Apply(ctx, d.plan)
	} else if err = d.armRollbackGuard(ctx); err == nil {
		err = f.ApplyProtected(ctx, d.plan)
	}
	if err != nil {
		d.planPending = true
		return nil, err
	}
	var after *netfilter.CheckFailure
	if verify || guarded {
		after = f.Check(ctx, d.plan)
	}
	if guarded && after != nil {
		d.planOn, d.planPending = false, true
		return after, d.armRollbackGuard(ctx)
	}
	// A firmware rebuild can remove a jump after its check has passed.
	// Keep the scoped drops active across the next ordinary repair as well.
	d.plan.GuardUnintercepted = d.plan.GuardUnintercepted || guarded
	d.planOn, d.planPending, d.planGuard = true, false, nil
	return after, nil
}

// protectPreviousPlan uses the last known protected sources when a normal
// rollback cannot restore its runtime dependencies or interception rules.
func (d *Daemon) protectPreviousPlan(previous netfilter.Plan) error {
	if d.planGuard == nil {
		if len(previous.Sources) == 0 {
			return nil
		}
		d.planGuard = &previous
	}
	d.planOn = false
	return d.armRollbackGuard(context.Background())
}

// armRollbackGuard installs the actual drops. The desired plan and shared
// filter jumps alone cannot prove that a previous guard write succeeded.
func (d *Daemon) armRollbackGuard(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := d.opt.Firewall.Protect(ctx, *d.planGuard); err != nil {
		return fmt.Errorf("install rollback guard: %w", err)
	}
	return nil
}

func (d *Daemon) detachStartupJumps() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// After a crash the old mode is unknown. TPROXY's plan includes the entry
	// jumps shared with REDIRECT, and Detach leaves all chains and routes alone.
	return d.opt.Firewall.Detach(ctx, netfilter.Plan{Mode: model.InterceptTProxy})
}

// checkFirewall runs under d.mu. A guard can be maintained even when the
// saved interception plan is waiting on its runtime dependencies.
func (d *Daemon) checkFirewall(ctx context.Context, trigger string) {
	if ctx.Err() != nil {
		return
	}
	if !d.planOn && !d.planPending {
		if d.planGuard != nil {
			if err := d.armRollbackGuard(ctx); err != nil && ctx.Err() == nil {
				d.log.Error("maintain rollback guard", "trigger", trigger, "err", err)
			}
		}
		return
	}
	started := time.Now()
	before := d.opt.Firewall.Check(ctx, d.plan)
	if ctx.Err() != nil || (before == nil && !d.planPending) {
		return
	}

	event := &journal.FirewallEvent{Trigger: trigger, Before: journalFirewallCheck(before)}
	d.repairFirewall(ctx, event)
	if ctx.Err() != nil {
		return
	}
	if event.Outcome == "restored" {
		d.restored++
	}
	duration := time.Since(started).Milliseconds()
	event.DurationMS = &duration
	d.recordFirewallRecovery(event)
}

// repairFirewall gives a firmware rebuild one bounded retry if rules disappear
// between installation and verification. The caller records the final outcome.
func (d *Daemon) repairFirewall(ctx context.Context, event *journal.FirewallEvent) {
	d.applyAndVerifyFirewall(ctx, event)
	if event.Outcome != "verify_failed" || ctx.Err() != nil {
		return
	}
	timer := time.NewTimer(firewallVerifyRetryDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
		if ctx.Err() == nil {
			d.applyAndVerifyFirewall(ctx, event)
		}
	}
}

func (d *Daemon) applyAndVerifyFirewall(ctx context.Context, event *journal.FirewallEvent) {
	after, err := d.applyFirewall(ctx, true)
	event.After, event.ApplyError, event.Restore = journalFirewallCheck(after), "", nil
	event.Outcome = "restored"
	if err != nil {
		event.Outcome, event.ApplyError = "apply_failed", err.Error()
		event.Restore = journalRestoreFailure(err)
	}
	if after != nil {
		event.Outcome = "verify_failed"
	}
}

func journalFirewallCheck(failure *netfilter.CheckFailure) *journal.FirewallCheck {
	if failure == nil {
		return nil
	}
	check := journal.FirewallCheck(*failure)
	return &check
}

func journalRestoreFailure(err error) *journal.RestoreDiagnostic {
	var f *netfilter.RestoreFailure
	if !errors.As(err, &f) {
		return nil
	}
	return &journal.RestoreDiagnostic{
		Wait: f.Wait, ExitCode: f.ExitCode, Line: f.Line, Table: f.Table,
		Operation: f.Operation, Chain: f.Chain, Target: f.Target,
	}
}

func (d *Daemon) recordFirewallRecovery(event *journal.FirewallEvent) {
	details := fmt.Sprintf("trigger: %s; check and recovery: %d ms; outcome: %s; verified restorations since start: %d", event.Trigger, *event.DurationMS, event.Outcome, d.restored)
	if event.Before != nil {
		details += "; before: " + event.Before.String()
	}
	if event.ApplyError != "" {
		details += "; apply: " + event.ApplyError
	}
	if event.After != nil {
		details += "; after: " + event.After.String()
	}
	action, result := "Interception rules not restored", "error"
	if event.Outcome == "restored" {
		action, result = "Interception rules restored", "warn"
	} else {
		d.log.Error("rule restoration failed", "trigger", event.Trigger, "details", details)
	}
	d.auditEntry(journal.Entry{
		Actor: "watchdog", Action: action, Target: "firewall", Result: result,
		Details: details, Firewall: event,
	})
}
