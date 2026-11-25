package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	M "github.com/sagernet/sing/common/metadata"
)

type diagnosticTransport func(*http.Request) (*http.Response, error)

func (f diagnosticTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func useLocalDiagnostic(t *testing.T) *atomic.Int64 {
	t.Helper()
	hits := new(atomic.Int64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	tests := diagnosticTests
	diagnosticTests = []diagnosticTest{{kind: "http", url: server.URL}}
	t.Cleanup(func() { diagnosticTests = tests })
	return hits
}

func startDiagnosticCore(t *testing.T, cfg *model.Config) *Daemon {
	t.Helper()
	cfg.Defaults()
	raw, err := compile.ConnectionSettingsConfig(compile.Input{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: cfg}
	if _, err := d.eng.Apply(raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.eng.Close() })
	return d
}

func TestDiagnosticTargetRefusesDetourThroughReachableReserve(t *testing.T) {
	hits := useLocalDiagnostic(t)
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var proxyHits atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := proxy.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var request [9]byte // a SOCKS4 connect to the local fixture with no username
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			return
		}
		proxyHits.Add(1)
		if _, err := conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		if r, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
			_ = r.Body.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		}
	}()
	t.Cleanup(func() { _ = proxy.Close(); <-done })
	d := startDiagnosticCore(t, &model.Config{Connections: []model.Connection{
		{ID: "disabled", Type: model.ConnLink, Link: "socks5://192.0.2.1:1080", Disabled: true, Fallback: "reserve"},
		{ID: "dependent", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "socks", "version": "4", "server": "127.0.0.1", "server_port": proxy.Addr().(*net.TCPAddr).Port, "detour": "disabled",
		}},
		{ID: "group", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"disabled"}}},
		{ID: "alias", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"failover-disabled"}}},
		{ID: "reserve", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
	}})
	d.chains = []compile.FailoverChain{{ID: "disabled", Tag: "failover-disabled"}}
	rev := model.ConfigRevision(d.Config())
	control, err := d.DiagnosticTargetIfCurrent(t.Context(), "reserve", rev)
	if err != nil || len(control.Results) != 1 || !control.Results[0].OK || hits.Load() != 1 {
		t.Fatal("the local reserve control could not reach the diagnostic endpoint")
	}
	for _, target := range []string{"dependent", "group", "alias"} {
		result, err := d.DiagnosticTargetIfCurrent(t.Context(), target, rev)
		if !errors.Is(err, engine.ErrDiagnosticPath) || len(result.Results) != 0 || proxyHits.Load() != 0 || hits.Load() != 1 {
			t.Errorf("%s diagnostic did not refuse the reserve before dialing, proxy hits %d", target, proxyHits.Load())
		}
	}
}

func TestDiagnosticTargetUsesSelectedConcreteLeaf(t *testing.T) {
	hits := useLocalDiagnostic(t)
	d := startDiagnosticCore(t, &model.Config{Connections: []model.Connection{
		{ID: "main", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"nested"}}},
		{ID: "nested", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "selector", "outbounds": []string{"first", "selected"}, "default": "selected",
		}},
		{ID: "first", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
		{ID: "selected", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
	}})
	report, err := d.DiagnosticTargetIfCurrent(t.Context(), "main", model.ConfigRevision(d.Config()))
	if err != nil || report.Connection != "selected" || len(report.Results) != 1 || !report.Results[0].OK || hits.Load() != 1 {
		t.Fatalf("expected the selected leaf to run the check, got %q, %d hits, error %v", report.Connection, hits.Load(), err)
	}
}

func TestDiagnosticNodeLabelsProtectProviderTextAndProfileCredentials(t *testing.T) {
	source := subscription.Source{ID: "main", URL: "https://feed.example.test/private-source"}
	socks := func(password string) string {
		return "socks5://" + url.UserPassword("fixture-operator", password).String() + "@proxy.example.test:1080"
	}
	const uuid = "a7e68fbacd3640799c4afa7b5c8d93a2"
	long := strings.Repeat("fixture-secret-", 20)
	cases := []struct{ link, label, want string }{
		{"vless://" + uuid + "@proxy.example.test:443", "Region A7E68FBA-CD36-4079-9C4A-FA7B5C8D93A2", ""},
		{socks(base64.StdEncoding.EncodeToString([]byte("fixture-private"))), "Region FIXTURE-PRIVATE", ""},
		{socks(long), long, ""},
		{socks("other-secret"), "Region " + source.URL, "Region [redacted]"},
		{socks("other-secret"), "Safe region", "Safe region"},
	}
	d := New(Options{})
	snapshot := subscriptionSnapshot{}
	for i, tc := range cases {
		snapshot.Nodes = append(snapshot.Nodes, subscription.Node{
			ID: strings.Repeat(string(rune('a'+i)), 32), Link: tc.link + "#" + url.PathEscape(tc.label), Name: tc.label,
		})
	}
	d.restoreSnapshotDisplay(source, &snapshot)
	d.subscriptions.states = map[string]appliedSubscription{source.ID: {snapshot: snapshot, source: source}}
	for i, node := range snapshot.Nodes {
		tag := model.ManagedTarget(source.ID, node.ID)
		label := d.DiagnosticNode(tag)
		if label.Name != cases[i].want || label.Position != i+1 {
			t.Errorf("node %d did not keep its safe display name and position", i+1)
		}
	}
}

func TestDiagnosticReportCapturesSubscriptionNodeAtTheCheck(t *testing.T) {
	hits := useLocalDiagnostic(t)
	first, second := strings.Repeat("a", 32), strings.Repeat("b", 32)
	firstTag, secondTag := model.ManagedTarget("main", first), model.ManagedTarget("main", second)
	auto := model.ManagedTarget("main", "auto")
	// Direct test outbounds stand in for the two compiled subscription members.
	d := startDiagnosticCore(t, &model.Config{Connections: []model.Connection{
		{ID: firstTag, Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
		{ID: secondTag, Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
	}})
	state := appliedSubscription{}
	state.snapshot.Nodes = []subscription.Node{
		{ID: first, Name: "First region", Link: "socks5://proxy.example.test:1080#First%20region"},
		{ID: second, Name: "PASSWORD", Link: "socks5://test:password@proxy.example.test:1080#PASSWORD"},
	}
	d.subscriptions.states = map[string]appliedSubscription{"main": state}
	d.subscriptions.members = []string{firstTag, secondTag}
	d.subscriptions.selectors = []compile.SubscriptionSelector{{SourceID: "main", Tag: auto, Candidates: []string{firstTag, secondTag}}}
	rev := model.ConfigRevision(d.Config())
	one, err := d.DiagnosticTargetIfCurrent(t.Context(), auto, rev)
	if err != nil || one.Connection != firstTag || one.CheckedAt.IsZero() ||
		one.Node != (DiagnosticNode{Name: "First region", Position: 1}) {
		t.Fatal("automatic diagnostic lost its tested node on reserve")
	}
	state.snapshot.Selection.Node = second
	d.subscriptions.states["main"] = state
	two, err := d.DiagnosticTargetIfCurrent(t.Context(), auto, rev)
	if err != nil || two.Connection != secondTag || two.CheckedAt.Before(one.CheckedAt) ||
		two.Node != (DiagnosticNode{Position: 2}) || hits.Load() != 2 {
		t.Fatal("same-revision change did not produce a second protected node observation")
	}
}

func TestDiagnosticTargetKeepsReserveOutOfTheCheck(t *testing.T) {
	tag := model.ManagedTarget("main", strings.Repeat("a", 32))
	secondNode := strings.Repeat("c", 32)
	second := model.ManagedTarget("main", secondNode)
	auto := model.ManagedTarget("main", "auto")
	balance := model.ManagedTarget("main", model.SubscriptionRoundRobin)
	missing := model.ManagedTarget("main", strings.Repeat("b", 32))
	d := &Daemon{cfg: &model.Config{Connections: []model.Connection{
		{ID: "primary", Fallback: "reserve"},
		{ID: "disabled", Disabled: true, Fallback: "reserve"},
	}}}
	d.targetAliases = map[string]string{"primary": "failover-primary", missing: "reserve"}
	d.subscriptions.members = []string{tag, second}
	d.subscriptions.selectors = []compile.SubscriptionSelector{{SourceID: "main", Tag: auto, Candidates: []string{tag, second}, Fallback: "reserve"}}
	d.subscriptions.balances = []compile.SubscriptionBalance{{Tag: balance, Candidates: []string{tag, second}, Fallback: "reserve"}}
	rev := model.ConfigRevision(d.Config())
	// Report.Connection identifies the outbound even when the test has no
	// running engine. Empty selections simulate automatic routing on reserve.
	assertTarget := func(target, want string) {
		t.Helper()
		report, err := d.DiagnosticTargetIfCurrent(t.Context(), target, rev)
		if !errors.Is(err, ErrDiagnosticConnection) || report.Connection != want {
			t.Errorf("target %s resolved to %q, error %v, want %q", target, report.Connection, err, want)
		}
	}
	for target, want := range map[string]string{"primary": "primary", tag: tag, auto: tag, balance: tag} {
		assertTarget(target, want)
	}
	state := appliedSubscription{}
	state.snapshot.Selection.Node = secondNode
	d.subscriptions.states = map[string]appliedSubscription{"main": state}
	d.health = map[string]*health{second: {known: true, ok: true}}
	assertTarget(auto, second)
	assertTarget(balance, second)
	for _, target := range []string{missing, "disabled", "unknown", model.TargetBlock} {
		assertTarget(target, "")
	}
	if _, err := d.DiagnosticTargetIfCurrent(t.Context(), "primary", "stale"); !errors.Is(err, model.ErrConfigChanged) {
		t.Errorf("outdated configuration returned %v", err)
	}
}

func TestDiagnosticBoundsAndFailures(t *testing.T) {
	client := &http.Client{Transport: diagnosticTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme == "http" {
			return nil, errors.New("private-password must never reach UI")
		}
		size := 65536
		if r.URL.Host != "speed.cloudflare.com" {
			size = 0
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", size))), Header: make(http.Header)}, nil
	})}
	results := runDiagnosticChecks(context.Background(), client)
	if len(results) != 3 || results[0].OK || !results[1].OK || !results[2].OK || results[2].Bytes != 65536 {
		t.Fatalf("unexpected results: %+v", results)
	}
	if strings.Contains(results[0].Error, "private-password") {
		t.Fatal("secret in diagnostic error")
	}
	if results[1].Error != "" || results[2].Error != "" {
		t.Fatal("successful diagnostic contains an error")
	}
}
func TestDiagnosticShortDownloadAndHTTPFailure(t *testing.T) {
	client := &http.Client{Transport: diagnosticTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("error")), Header: make(http.Header)}, nil
	})}
	for _, r := range runDiagnosticChecks(context.Background(), client) {
		if r.OK {
			t.Fatalf("HTTP503 accepted: %+v", r)
		}
	}
	client.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("short")), Header: make(http.Header)}, nil
	})
	if runDiagnosticChecks(context.Background(), client)[2].OK {
		t.Fatal("short download accepted")
	}
}
func TestDiagnosticCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: diagnosticTransport(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })}
	for _, r := range runDiagnosticChecks(ctx, client) {
		if r.OK {
			t.Fatal("cancelled check passed")
		}
	}
}

func TestDiagnosticsRejectUnknownAndStoppedProfiles(t *testing.T) {
	d := &Daemon{cfg: &model.Config{Connections: []model.Connection{{ID: "one", Name: "One", Type: model.ConnLink}}}}
	for _, id := range []string{"missing", "one"} {
		if _, err := d.DiagnosticChecks(context.Background(), id); !errors.Is(err, ErrDiagnosticConnection) {
			t.Fatalf("%s: %v", id, err)
		}
	}
}
func TestDiagnosticProfileDialerAndCancellation(t *testing.T) {
	var profileContext context.Context
	client, peer := net.Pipe()
	defer peer.Close()
	dial := diagnosticDialer(context.Background(), func(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
		profileContext = ctx
		if network != "tcp" || target.Port != 443 || target.Addr.String() != "127.0.0.1" {
			t.Fatalf("wrong profile destination: %s %v", network, target)
		}
		return client, nil
	})
	conn, err := dial(context.Background(), "tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if profileContext.Err() != context.Canceled {
		t.Fatal("profile dial context leaked")
	}
	for _, address := range []string{"invalid", "127.0.0.1:bad"} {
		if _, err := dial(context.Background(), "tcp", address); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
}
func TestDiagnosticSlotCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if release, err := acquireDiagnosticSlot(ctx); err != context.Canceled || release != nil {
		t.Fatal("cancelled check acquired a slot")
	}
}

func TestDiagnosticResponseBoundaries(t *testing.T) {
	for _, status := range []int{199, 200, 299, 300} {
		r := &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("status response"))}
		count, _, err := diagnosticResponse(r, 0)
		if count != 0 || (err == nil) != (status >= 200 && status < 300) {
			t.Fatalf("status %d: %v", status, err)
		}
	}
	for _, size := range []int{0, 1, 65535, 65536, 65537, 70000} {
		r := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", size)))}
		count, _, err := diagnosticResponse(r, 65536)
		if (err == nil) != (size == 65536) || count > 65537 {
			t.Fatalf("size %d: count %d, %v", size, count, err)
		}
	}
}

func TestDiagnosticNetworkErrorsAreSanitized(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if diagnosticNetworkError(ctx, nil) != "check cancelled" {
		t.Fatal("cancellation lost")
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if diagnosticNetworkError(ctx, nil) != "check timed out" {
		t.Fatal("deadline lost")
	}
	client := &http.Client{Transport: diagnosticTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret") })}
	r := diagnosticRequest(context.Background(), client, diagnosticTest{kind: "https", url: "https://example.test"})
	if r.OK || r.Error != "network, DNS or TLS check failed" {
		t.Fatalf("unsafe result: %+v", r)
	}
	client.Transport = diagnosticTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	r = diagnosticRequest(context.Background(), client, diagnosticTest{kind: "https", url: "https://example.test"})
	if r.OK || r.Error != "HTTP 503" {
		t.Fatalf("HTTP status lost: %+v", r)
	}
}

func TestDiagnosticCheckDistinguishesTLSAndDNSFailures(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&tls.CertificateVerificationError{Err: errors.New("private target")}, "TLS check failed"},
		{&net.DNSError{Name: "private target", Err: "host not found"}, "DNS lookup failed"},
	} {
		client := &http.Client{Transport: diagnosticTransport(func(*http.Request) (*http.Response, error) {
			return nil, tc.err
		})}
		got := diagnosticRequest(t.Context(), client, diagnosticTest{kind: "https", url: "https://example.test"})
		if got.OK || got.Error != tc.want {
			t.Errorf("diagnostic returned %q, want %q", got.Error, tc.want)
		}
	}
}
