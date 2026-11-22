package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const subscriptionFirst = "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:12340?encryption=none#First"
const subscriptionSecond = "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:12341?encryption=none#Second"

type subscriptionTestResponse struct {
	body, title string
	headers     http.Header
}

type subscriptionTestProvider struct {
	response atomic.Pointer[subscriptionTestResponse]
	requests atomic.Int32
}

func (p *subscriptionTestProvider) RoundTrip(*http.Request) (*http.Response, error) {
	p.requests.Add(1)
	r := p.response.Load()
	headers := r.headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	headers.Set("profile-title", r.title)
	return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader(r.body))}, nil
}

func newSubscriptionTestDaemon(t *testing.T, provider http.RoundTripper) (*Daemon, *model.Config) {
	t.Helper()
	holdMemoryLimit(t)
	base := quietConfig(t)
	base.Failover.URL = "https://127.0.0.1:12342/"
	path := writeSavedConfig(t, base)
	d := newMemoryDaemon(t, path, &gateRunner{})
	d.subscriptions.fetcher = subscription.NewFetcher(filepath.Join(t.TempDir(), "identity"), provider)
	t.Cleanup(d.shutdown)
	base.Subscriptions = []subscription.Source{{ID: "sample", URL: "https://provider.example/sample-private-token"}}
	base.Groups = []model.Group{{Name: "Video", Target: "subscription:sample:auto", Entries: []string{"video.example"}}}
	return d, base
}

func runSubscriptionTestWorker(t *testing.T, d *Daemon) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runSubscriptions(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func awaitSubscriptionStatus(t *testing.T, d *Daemon, check func(SubscriptionStatus) bool) SubscriptionStatus {
	t.Helper()
	var status []SubscriptionStatus
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		status = d.Subscriptions()
		if len(status) == 1 && check(status[0]) {
			return status[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("unexpected subscription status: %+v", status)
	return SubscriptionStatus{}
}

func requireSubscriptionSelection(t *testing.T, d *Daemon, tag string) context.Context {
	t.Helper()
	out, ctx, ok := d.eng.Outbound("subscription:sample:auto")
	if !ok {
		t.Fatal("automatic route selector is absent")
	}
	if got := stats.Resolve(out).Tag(); got != tag {
		t.Fatalf("automatic route selects %q, want %q", got, tag)
	}
	return ctx
}

func TestSubscriptionPreviewApplyRefreshAndRestart(t *testing.T) {
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst + "\n" + subscriptionSecond, title: "Test provider"})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	source := cfg.Subscriptions[0]
	preview := d.PreviewSubscription(t.Context(), source)
	if preview.State != "ready" || len(preview.Nodes) != 2 || preview.Nodes[0].Name != "First" || len(d.Subscriptions()) != 0 {
		t.Fatalf("preview did not return two draft-only nodes: %+v", preview)
	}
	cfg.Groups = append(cfg.Groups, model.Group{Name: "Pinned", Target: model.ManagedTarget(source.ID, preview.Nodes[1].ID), Entries: []string{"pin.example"}})
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if got := provider.requests.Load(); got != 1 {
		t.Fatalf("Apply did not reuse the validated preview, requests=%d", got)
	}
	first := model.ManagedTarget(source.ID, preview.Nodes[0].ID)
	engineCtx := requireSubscriptionSelection(t, d, first)
	saved, err := os.ReadFile(d.opt.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	runSubscriptionTestWorker(t, d)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionSecond + "\n" + subscriptionFirst, title: "Updated notice"})
	if !d.RefreshSubscription(source.ID) {
		t.Fatal("applied subscription did not accept refresh")
	}
	beforeFailure := awaitSubscriptionStatus(t, d, func(got SubscriptionStatus) bool {
		return got.State == "ready" && got.Metadata.Title == "Updated notice"
	})
	if beforeFailure.Nodes[0].Name != "Second" || beforeFailure.ActiveNode != preview.Nodes[0].ID || requireSubscriptionSelection(t, d, first) != engineCtx {
		t.Fatalf("refresh did not preserve the active engine and expose provider order: %+v", beforeFailure)
	}

	provider.response.Store(&subscriptionTestResponse{headers: http.Header{"X-Hwid-Max-Devices-Reached": []string{"true"}}})
	d.RefreshSubscription(source.ID)
	afterFailure := awaitSubscriptionStatus(t, d, func(got SubscriptionStatus) bool { return got.State == "hwid_limit" })
	if len(afterFailure.Nodes) != 2 || afterFailure.LastSuccess == nil || !afterFailure.LastSuccess.Equal(*beforeFailure.LastSuccess) {
		t.Fatalf("device-limit response discarded the last working snapshot: %+v", afterFailure)
	}
	if raw, err := os.ReadFile(d.opt.ConfigPath); err != nil || !bytes.Equal(saved, raw) {
		t.Fatal("refresh changed the saved YAML")
	}
	file := d.subscriptionSnapshotPath(cfg)
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot is missing or publicly readable: %v, %v", info, err)
	}

	d.shutdown()
	reopened := New(d.opt)
	t.Cleanup(reopened.shutdown)
	if _, err := reopened.startLocked(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := reopened.Subscriptions()
	if len(got) != 1 || got[0].State != "ready" || got[0].ActiveNode != preview.Nodes[0].ID || got[0].Metadata.Title != "Updated notice" {
		t.Fatalf("last usable snapshot and active selection were not restored: %+v", got)
	}
	requireSubscriptionSelection(t, reopened, first)
}

func TestSubscriptionFailoverWaitsForFailureAndStaysOnReplacement(t *testing.T) {
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst + "\n" + subscriptionSecond})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	nodes := d.Subscriptions()[0].Nodes
	first, second := model.ManagedTarget("sample", nodes[0].ID), model.ManagedTarget("sample", nodes[1].ID)
	originalCtx := requireSubscriptionSelection(t, d, first)

	now := time.Now()
	d.health[first], d.health[second] = &health{}, &health{}
	d.health[first].record(false, 0, "unavailable", now)
	d.health[second].record(true, time.Millisecond, "", now)
	d.switchSubscriptionsLocked(now.Add(59 * time.Second))
	requireSubscriptionSelection(t, d, first)
	d.switchSubscriptionsLocked(now.Add(60 * time.Second))
	requireSubscriptionSelection(t, d, first)
	d.health[second].record(true, time.Millisecond, "", now.Add(time.Minute))
	d.switchSubscriptionsLocked(now.Add(60 * time.Second))
	if requireSubscriptionSelection(t, d, second) != originalCtx {
		t.Fatal("live failover restarted the core")
	}
	status := d.Subscriptions()[0]
	if status.ActiveNode != nodes[1].ID || status.SwitchReason != "failure" || status.LastSwitch == nil || status.Unavailable {
		t.Fatalf("successful failover status: %+v", status)
	}

	d.health[first].record(true, time.Millisecond, "", now.Add(time.Minute))
	d.switchSubscriptionsLocked(now.Add(10 * time.Minute))
	requireSubscriptionSelection(t, d, second)
	d.health[first].record(false, 0, "unavailable", now.Add(11*time.Minute))
	d.health[second].record(false, 0, "unavailable", now.Add(11*time.Minute))
	d.switchSubscriptionsLocked(now.Add(12 * time.Minute))
	requireSubscriptionSelection(t, d, second)
	if !d.Subscriptions()[0].Unavailable {
		t.Fatal("all candidates are down but automatic route is advertised as available")
	}
}

func TestSubscriptionRefreshStorageFailurePreservesRunningSnapshot(t *testing.T) {
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	before := d.Subscriptions()[0]
	path := d.subscriptionSnapshotPath(cfg)
	if err := os.Rename(path, path+".before"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	provider.response.Store(&subscriptionTestResponse{body: subscriptionSecond})
	runSubscriptionTestWorker(t, d)
	d.RefreshSubscription("sample")
	after := awaitSubscriptionStatus(t, d, func(got SubscriptionStatus) bool { return got.State == "activation_error" })
	if len(after.Nodes) != 1 || after.Nodes[0].ID != before.ActiveNode || !after.LastSuccess.Equal(*before.LastSuccess) {
		t.Fatalf("uncommitted candidate leaked into applied status: %+v", after)
	}
	requireSubscriptionSelection(t, d, model.ManagedTarget("sample", before.ActiveNode))
}

func TestSubscriptionSnapshotKeepsTwoSavedGenerations(t *testing.T) {
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	var paths []string
	for _, endpoint := range []string{"first", "second", "third"} {
		cfg.Subscriptions[0].URL = "https://provider.example/" + endpoint
		if err := d.Apply(t.Context(), cfg); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, d.subscriptionSnapshotPath(cfg))
		cfg = d.Config()
	}
	if _, err := os.Stat(paths[0]); !os.IsNotExist(err) {
		t.Fatalf("oldest private snapshot survived two config saves: %v", err)
	}
	for _, path := range paths[1:] {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("snapshot for current or previous YAML was lost: %v", err)
		}
	}
}

func TestSubscriptionProbeBatchPrioritizesActiveAndPinnedNodes(t *testing.T) {
	d := New(Options{RuleSetDir: t.TempDir()})
	d.cfg = &model.Config{Failover: model.Failover{Interval: 15}}
	now := time.Now()
	tags := make([]string, 47)
	for i := range tags {
		tags[i] = model.ManagedTarget("sample", fmt.Sprintf("%032x", i+1))
	}
	_, activeID, _ := model.ParseManagedTarget(tags[46])
	d.subscriptions.states = map[string]appliedSubscription{
		"sample": {snapshot: subscriptionSnapshot{Selection: subscriptionSelection{Node: activeID}}},
	}
	d.subscriptions.members = tags
	d.subscriptions.selectors = []compile.SubscriptionSelector{{SourceID: "sample", Candidates: tags}}
	d.cfg.Groups = []model.Group{{Name: "Pinned", Target: tags[45]}}
	batch, _ := d.subscriptionProbeBatchLocked(now)
	if !slices.Equal(batch, []string{tags[46], tags[45], tags[0], tags[1]}) {
		t.Fatalf("expected a bounded batch prioritizing active, pinned and provider order: %v", batch)
	}
	for _, tag := range batch {
		d.health[tag] = &health{checked: now, known: true}
	}
	batch, _ = d.subscriptionProbeBatchLocked(now)
	if !slices.Equal(batch, tags[2:6]) {
		t.Fatalf("healthy probe cadence starved untouched candidates: %v", batch)
	}
}

func TestSubscriptionRefreshIgnoresReplacedSource(t *testing.T) {
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	d.RefreshSubscription("sample")
	d.mu.Lock()
	request := d.nextSubscriptionRefreshLocked(time.Now())
	d.mu.Unlock()
	if request == nil {
		t.Fatal("scheduled refresh was not claimed by the worker")
	}
	stale := d.fetchSubscription(t.Context(), request.source)

	cfg = d.Config()
	cfg.Subscriptions[0].URL = "https://provider.example/replacement"
	provider.response.Store(&subscriptionTestResponse{body: subscriptionSecond})
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.finishSubscriptionRefreshLocked(request, stale)
	d.mu.Unlock()
	got := d.Subscriptions()[0]
	if len(got.Nodes) != 1 || got.Nodes[0].Name != "Second" {
		t.Fatalf("old provider overrode the replacement configuration: %+v", got)
	}
}

func TestSubscriptionRefreshReconcilesTheCoreWithoutFirewallOrDNS(t *testing.T) {
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	dns := d.dns
	active := model.ManagedTarget("sample", d.Subscriptions()[0].ActiveNode)
	before := requireSubscriptionSelection(t, d, active)
	// Simulate an existing firewall that cannot be reinstalled during refresh.
	d.opt.Firewall.Run = &gateRunner{fail: true}
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst + "\n" + subscriptionSecond})
	runSubscriptionTestWorker(t, d)
	d.RefreshSubscription("sample")
	got := awaitSubscriptionStatus(t, d, func(status SubscriptionStatus) bool {
		return len(status.Nodes) == 2 || status.State == "activation_error"
	})
	if got.State != "ready" || len(got.Nodes) != 2 || d.dns != dns {
		t.Fatalf("refresh depended on or replaced unrelated runtime services: %+v", got)
	}
	if requireSubscriptionSelection(t, d, active) == before {
		t.Fatal("changed outbound set was not activated")
	}
}

func TestSubscriptionRemovalBlocksUntilReplacementResponds(t *testing.T) {
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst + "\n" + subscriptionSecond})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	second := model.ManagedTarget("sample", d.Subscriptions()[0].Nodes[1].ID)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionSecond})
	runSubscriptionTestWorker(t, d)
	d.RefreshSubscription("sample")
	got := awaitSubscriptionStatus(t, d, func(status SubscriptionStatus) bool { return len(status.Nodes) == 1 })
	if got.ActiveNode != "" || !got.Unavailable || got.SwitchReason != "removed" {
		t.Fatalf("removed active did not leave an unavailable selector: %+v", got)
	}
	requireSubscriptionSelection(t, d, model.TargetBlock)

	now := time.Now()
	d.mu.Lock()
	d.health[second] = &health{}
	d.health[second].record(true, time.Millisecond, "", now)
	d.switchSubscriptionsLocked(now)
	d.mu.Unlock()
	requireSubscriptionSelection(t, d, second)
	if got := d.Subscriptions()[0]; got.Unavailable || got.SwitchReason != "removed" {
		t.Fatalf("verified replacement did not clear the unavailable state: %+v", got)
	}
}

func TestSubscriptionSnapshotRejectsCorruptNodeIdentity(t *testing.T) {
	for _, corrupt := range []string{"mismatched link", "duplicate ID"} {
		t.Run(corrupt, func(t *testing.T) {
			provider := new(subscriptionTestProvider)
			provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst + "\n" + subscriptionSecond})
			d, cfg := newSubscriptionTestDaemon(t, provider)
			if err := d.Apply(t.Context(), cfg); err != nil {
				t.Fatal(err)
			}
			path := d.subscriptionSnapshotPath(cfg)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var snapshots map[string]subscriptionSnapshot
			if err := json.Unmarshal(raw, &snapshots); err != nil {
				t.Fatal(err)
			}
			for _, snapshot := range snapshots {
				if corrupt == "mismatched link" {
					snapshot.Nodes[0].Link = snapshot.Nodes[1].Link
				} else {
					snapshot.Nodes[1] = snapshot.Nodes[0]
				}
			}
			raw, err = json.Marshal(snapshots)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}

			d.shutdown()
			reopened := New(d.opt)
			t.Cleanup(reopened.shutdown)
			if _, err := reopened.startLocked(t.Context()); err != nil {
				t.Fatal(err)
			}
			got := reopened.Subscriptions()[0]
			if got.State != "pending" || len(got.Nodes) != 0 || !got.Unavailable {
				t.Fatalf("corrupt private snapshot was reused: %+v", got)
			}
		})
	}
}
