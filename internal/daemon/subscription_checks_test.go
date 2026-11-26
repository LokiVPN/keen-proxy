package daemon

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestPageSubscriptionCheckRequiresCurrentConfig(t *testing.T) {
	const id, nodeID = "sample", "aabbccddeeff00112233445566778899"
	d := &Daemon{
		cfg: &model.Config{Subscriptions: []subscription.Source{{ID: id, URL: "https://provider.example/saved"}}},
		subscriptions: subscriptionRuntime{
			states:    map[string]appliedSubscription{id: {snapshot: subscriptionSnapshot{Nodes: []subscription.Node{{ID: nodeID}}}}},
			probeWake: make(chan struct{}, 1),
		},
	}
	checker, ok := any(d).(interface {
		CheckSubscriptionIfCurrent(string, string, string) error
	})
	if !ok {
		t.Fatal("page requests have no revision-checked entry point for saved probes")
	}
	stale := model.ConfigRevision(d.Config())
	d.cfg.Subscriptions[0].URL = "https://provider.example/replaced"
	if err := checker.CheckSubscriptionIfCurrent(id, "", stale); !errors.Is(err, model.ErrConfigChanged) {
		t.Fatalf("stale all-node check returned %v", err)
	}
	if got := d.Subscriptions()[0]; got.CheckProgress != nil || got.Nodes[0].Checking || len(d.subscriptions.probeWake) != 0 {
		t.Fatal("stale request queued subscription probes")
	}
	current := model.ConfigRevision(d.Config())
	if err := checker.CheckSubscriptionIfCurrent(id, "removed-node", current); err == nil {
		t.Fatal("a removed node was accepted for checking")
	}
	if err := checker.CheckSubscriptionIfCurrent(id, nodeID, current); err != nil {
		t.Fatal(err)
	}
	if got := d.Subscriptions()[0]; got.CheckProgress != nil || !got.Nodes[0].Checking || len(d.subscriptions.probeWake) != 1 {
		t.Fatal("the requested node was not queued for checking")
	}
	if err := checker.CheckSubscriptionIfCurrent(id, "", current); err != nil {
		t.Fatal(err)
	}
	if got := d.Subscriptions()[0].CheckProgress; got == nil || got.Total != 1 || got.Completed != 0 {
		t.Fatalf("the saved catalog was not queued for checking: %+v", got)
	}
}

// This fixture refuses SOCKS handshakes at a loopback listener. Each completed
// check must open a connection to it through the corresponding saved profile.
func TestSubscriptionCheckVisitsSavedCatalogWithoutRoutes(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections atomic.Int32
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-serverDone })

	const count = 47
	var listing strings.Builder
	for i := range count {
		fmt.Fprintf(&listing, "socks5://node%d:test-secret@%s#Node-%d\n", i, listener.Addr(), i)
	}
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: listing.String()})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	cfg.Groups = nil
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	status := d.Subscriptions()[0]
	if len(status.Nodes) != count {
		t.Fatalf("want %d usable nodes, got %d", count, len(status.Nodes))
	}
	nodeID := status.Nodes[count-1].ID
	rev := model.ConfigRevision(d.Config())
	for _, node := range []string{"", "", nodeID} {
		if err := d.CheckSubscriptionIfCurrent("sample", node, rev); err != nil {
			t.Fatalf("queue check for %q: %v", node, err)
		}
	}
	if err := d.CheckSubscriptionIfCurrent("sample", "invalid", rev); err == nil {
		t.Fatal("accepted an unknown node")
	}
	type nodeCheck struct {
		Checking bool       `json:"checking"`
		Time     *time.Time `json:"checked_at"`
		Error    string     `json:"check_error"`
	}
	type progress struct {
		Total     int
		Completed int
	}
	read := func(status SubscriptionStatus) ([]nodeCheck, *progress) {
		t.Helper()
		raw, err := json.Marshal(status)
		var decoded struct {
			Nodes    []nodeCheck
			Progress *progress `json:"check_progress"`
		}
		if err != nil || json.Unmarshal(raw, &decoded) != nil {
			t.Fatal("invalid check status")
		}
		if strings.Contains(string(raw), "test-secret") {
			t.Fatal("check status disclosed a credential")
		}
		return decoded.Nodes, decoded.Progress
	}
	nodes, queued := read(d.Subscriptions()[0])
	if queued == nil || *queued != (progress{Total: count}) || !nodes[count-1].Checking {
		t.Fatalf("duplicate requests did not coalesce into a pending catalog: %+v", queued)
	}

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		defer close(done)
		d.runSubscriptionHealth(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
	status = awaitSubscriptionStatus(t, d, func(status SubscriptionStatus) bool {
		_, check := read(status)
		return check == nil
	})
	nodes, _ = read(status)
	for i, node := range nodes {
		if node.Time == nil || node.Checking || node.Error == "" {
			t.Fatalf("node %d did not report a completed sanitized failure: %+v", i, node)
		}
	}
	if got := connections.Load(); got != count {
		t.Fatalf("observed %d node connections for %d checks", got, count)
	}
	if status.LastSuccess == nil {
		t.Fatal("node testing changed successful subscription download status")
	}
}

func TestSubscriptionCheckDiscardsCompletionAfterSourceReplacement(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- conn:
			case <-t.Context().Done():
				_ = conn.Close()
				return
			}
		}
	}()
	waitProbe := func() net.Conn {
		t.Helper()
		select {
		case conn := <-accepted:
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		case <-time.After(5 * time.Second):
			t.Fatal("queued probe did not dial the synthetic node")
			return nil
		}
	}

	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: "socks5://" + listener.Addr().String() + "#Node"})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	cfg.Groups = nil
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	nodeID := d.Subscriptions()[0].Nodes[0].ID
	if err := d.CheckSubscriptionIfCurrent("sample", nodeID, model.ConfigRevision(d.Config())); err != nil {
		t.Fatalf("initial check: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runSubscriptionHealth(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })

	first := waitProbe()
	replacement := cfg.Clone()
	replacement.Subscriptions[0].URL = "https://provider.example/replacement"
	if err := d.Apply(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckSubscriptionIfCurrent("sample", nodeID, model.ConfigRevision(d.Config())); err != nil {
		t.Fatalf("replacement check: %v", err)
	}
	_ = first.Close()
	second := waitProbe()
	node := d.Subscriptions()[0].Nodes[0]
	if !node.Checking || node.CheckedAt != nil {
		t.Fatalf("old completion entered the replacement status: %+v", node)
	}
	_ = second.Close()
	awaitSubscriptionStatus(t, d, func(status SubscriptionStatus) bool {
		node := status.Nodes[0]
		return !node.Checking && node.CheckedAt != nil
	})
}

func TestSubscriptionBatchKeepsAllDuePriorityClasses(t *testing.T) {
	var d Daemon
	tags := d.subscriptionProbeBatch([]subscriptionProbe{
		{tag: "active-1", priority: probeActive},
		{tag: "active-2", priority: probeActive},
		{tag: "requested", priority: probeRequested, isolated: true},
		{tag: "candidate", priority: probeCandidate},
		{tag: "pin", priority: probePinned},
		{tag: "isolated-candidate", priority: probeCandidate, isolated: true},
	})
	if got := strings.Join(tags, ","); got != "active-1,requested,pin,candidate" {
		t.Fatalf("missing a due class or exceeded isolation limit: %s", got)
	}
}

func TestSubscriptionDetachedSweepProgressesDuringRepeatedSingleChecks(t *testing.T) {
	source := subscription.Source{ID: "sample", URL: "https://provider.example/list"}
	single, sweep := strings.Repeat("a", 32), strings.Repeat("b", 32)
	d := New(Options{RuleSetDir: t.TempDir()})
	d.cfg = &model.Config{Subscriptions: []subscription.Source{source}, Failover: model.Failover{Interval: 15}}
	d.subscriptions.states = map[string]appliedSubscription{
		source.ID: {
			source:   source,
			snapshot: subscriptionSnapshot{Nodes: []subscription.Node{{ID: single}, {ID: sweep}}},
			checks: subscriptionChecks{pending: map[string]subscriptionCheckFlags{
				single: checkSingle,
				sweep:  checkCatalog,
			}},
		},
	}
	for i, id := range []string{single, sweep, single, sweep} {
		batch, _ := d.subscriptionProbeBatchLocked(time.Now())
		if want := model.ManagedTarget(source.ID, id); len(batch) != 1 || batch[0] != want {
			t.Fatalf("batch %d = %v, want only %s", i, batch, want)
		}
	}
}

func TestSubscriptionCheckRejectsManagementOnlyStartup(t *testing.T) {
	d := New(Options{RuleSetDir: t.TempDir()})
	d.cfg = &model.Config{Subscriptions: []subscription.Source{{ID: "sample", URL: "https://provider.example/saved"}}}
	d.startupBlocked = make(chan struct{})
	d.subscriptions.states = map[string]appliedSubscription{
		"sample": {snapshot: subscriptionSnapshot{Nodes: []subscription.Node{{ID: strings.Repeat("a", 32)}}}},
	}
	if err := d.CheckSubscriptionIfCurrent("sample", "", model.ConfigRevision(d.Config())); err == nil || errors.Is(err, model.ErrConfigChanged) {
		t.Fatalf("check while startup is blocked: %v", err)
	}
}

func TestSubscriptionTLSProbeFeedsTheBalancedRoute(t *testing.T) {
	// Process isolation keeps the test CA from changing trust for other tests.
	const child = "KEENPROXY_SYNTHETIC_SUBSCRIPTION_TLS"
	if os.Getenv(child) != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSubscriptionTLSProbeFeedsTheBalancedRoute$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), child+"=1", "GODEBUG=x509usefallbackroots=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated TLS check: %v\n%s", err, output)
		}
		return
	}
	var requests atomic.Int32
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(site.Close)
	roots := x509.NewCertPool()
	roots.AddCert(site.Certificate())
	x509.SetFallbackRoots(roots)

	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := proxy.Accept()
			if err != nil {
				return
			}
			go forwardSubscriptionTestSOCKS(conn, site.Listener.Addr().String())
		}
	}()
	t.Cleanup(func() { _ = proxy.Close(); <-done })
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailable := closed.Addr().String()
	_ = closed.Close()
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: fmt.Sprintf("socks5://%s#Working\nsocks5://%s#Unavailable", proxy.Addr(), unavailable)})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	const balance = "subscription:sample:round-robin"
	cfg.Groups[0].Target = balance
	cfg.Failover.URL = site.URL
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if status := d.Subscriptions()[0]; status.BalanceEligible == nil || *status.BalanceEligible != 0 {
		t.Fatal("a new route should wait for a successful check")
	}
	if err := d.CheckSubscriptionIfCurrent("sample", "", model.ConfigRevision(d.Config())); err != nil {
		t.Fatalf("catalog check: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		d.runSubscriptionHealth(ctx)
	}()
	t.Cleanup(func() { cancel(); <-workerDone })
	status := awaitSubscriptionStatus(t, d, func(status SubscriptionStatus) bool {
		return status.CheckProgress == nil && status.BalanceEligible != nil && *status.BalanceEligible == 1
	})
	if status.Nodes[0].LatencyMS == nil || status.Nodes[1].CheckError == "" || requests.Load() != 1 {
		t.Fatalf("expected one measured HTTPS success and one checked failure: %+v", status.Nodes)
	}
	out, engineContext, ok := d.eng.Outbound(balance)
	if !ok {
		t.Fatal("applied balance is absent from the engine")
	}
	result := probeSubscriptionOutbound(t.Context(), engineContext, out.DialContext, diagnosticTest{kind: "https", url: site.URL})
	if !result.OK || requests.Load() != 2 {
		t.Fatalf("the applied balance could not use its verified member: %+v", result)
	}
}

// forwardSubscriptionTestSOCKS accepts a SOCKS5 CONNECT and forwards only to
// the fixed loopback TLS fixture.
func forwardSubscriptionTestSOCKS(conn net.Conn, target string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting[0] != 5 {
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [10]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil || request[0] != 5 || request[1] != 1 || request[3] != 1 {
		return
	}
	upstream, err := net.DialTimeout("tcp4", target, time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	<-finished
}
