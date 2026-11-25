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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/sagernet/sing-box/adapter"
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

func useLocalDiagnosticSOCKS(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
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
		var request [10]byte // SOCKS5 CONNECT to the local IPv4 fixture
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			return
		}
		proxyHits.Add(1)
		if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			return
		}
		if r, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
			_ = r.Body.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		}
	}()
	t.Cleanup(func() { _ = proxy.Close(); <-done })
	return proxy.Addr().(*net.TCPAddr).Port, &proxyHits
}

func TestDiagnosticTargetRefusesDetourThroughReachableReserve(t *testing.T) {
	hits := useLocalDiagnostic(t)
	port, proxyHits := useLocalDiagnosticSOCKS(t)
	d := startDiagnosticCore(t, &model.Config{Connections: []model.Connection{
		{ID: "disabled", Type: model.ConnLink, Link: "socks5://192.0.2.1:1080", Disabled: true, Fallback: "reserve"},
		{ID: "disabled-vpn", Type: model.ConnLink, Link: "socks5://192.0.2.1:1080", Disabled: true, Fallback: "reserve-vpn"},
		{ID: "dependent", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "socks", "version": "5", "server": "127.0.0.1", "server_port": port, "detour": "disabled",
		}},
		{ID: "group", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"disabled"}}},
		{ID: "alias", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"failover-disabled"}}},
		{ID: "group-with-vpn-reserve", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"failover-disabled-vpn"}}},
		{ID: "reserve", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
		{ID: "reserve-vpn", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "socks", "version": "5", "server": "127.0.0.1", "server_port": port,
		}},
	}})
	d.chains = []compile.FailoverChain{
		{ID: "disabled", Tag: "failover-disabled"},
		{ID: "disabled-vpn", Tag: "failover-disabled-vpn"},
	}
	rev := model.ConfigRevision(d.Config())
	control, err := d.DiagnosticTargetIfCurrent(t.Context(), "reserve", rev)
	if err != nil || len(control.Results) != 1 || !control.Results[0].OK || hits.Load() != 1 {
		t.Fatal("the local reserve control could not reach the diagnostic endpoint")
	}
	dependent, err := d.DiagnosticTargetIfCurrent(t.Context(), "dependent", rev)
	if !errors.Is(err, engine.ErrDiagnosticPath) || len(dependent.Results) != 0 || proxyHits.Load() != 0 {
		t.Fatal("the raw detour reached its proxy through the disabled hop")
	}
	for target, leaf := range map[string]string{"group": "reserve", "alias": "reserve", "group-with-vpn-reserve": "reserve-vpn"} {
		result, err := d.DiagnosticTargetIfCurrent(t.Context(), target, rev)
		if err != nil || !result.SkippedVPN || result.Group != target || result.Connection != leaf ||
			len(result.Results) != 0 || proxyHits.Load() != 0 || hits.Load() != 1 {
			t.Errorf("%s diagnostic did not report and skip the selected reserve, proxy hits %d", target, proxyHits.Load())
		}
	}
}

func TestDiagnosticTargetUsesSelectedConcreteLeaf(t *testing.T) {
	hits := useLocalDiagnostic(t)
	port, proxyHits := useLocalDiagnosticSOCKS(t)
	d := startDiagnosticCore(t, &model.Config{Connections: []model.Connection{
		{ID: "main", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"nested"}}},
		{ID: "nested", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "selector", "outbounds": []string{"first", "selected", "reject"}, "default": "selected",
		}},
		{ID: "first", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
		{ID: "direct-alias", Type: model.ConnSingBox, Outbound: map[string]any{"type": "selector", "outbounds": []string{"first"}}},
		{ID: "selected", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "socks", "version": "5", "server": "127.0.0.1", "server_port": port,
		}},
		{ID: "reject", Type: model.ConnSingBox, Outbound: map[string]any{"type": "block"}},
	}})
	rev := model.ConfigRevision(d.Config())
	report, err := d.DiagnosticTargetIfCurrent(t.Context(), "main", rev)
	if err != nil || report.Group != "main" || report.Connection != "selected" || report.SkippedVPN ||
		len(report.Results) != 1 || !report.Results[0].OK || proxyHits.Load() != 1 || hits.Load() != 0 {
		t.Fatalf("expected the selected leaf to run the check, got %q, %d proxy hits, error %v", report.Connection, proxyHits.Load(), err)
	}
	if !d.eng.Select("nested", "reject") {
		t.Fatal("could not select the block leaf")
	}
	blocked, err := d.DiagnosticTargetIfCurrent(t.Context(), "main", rev)
	if err != nil || !blocked.SkippedVPN || blocked.Group != "main" || blocked.Connection != "reject" ||
		len(blocked.Results) != 0 || hits.Load() != 0 {
		t.Fatal("the selected block leaf was not reported as skipped")
	}
	direct, err := d.DiagnosticTargetIfCurrent(t.Context(), "direct-alias", rev)
	if err != nil || direct.SkippedVPN || direct.Group != "direct-alias" || direct.Connection != "first" ||
		len(direct.Results) != 1 || !direct.Results[0].OK || hits.Load() != 1 {
		t.Fatal("the single direct target did not preserve its connectivity check")
	}
}

func TestDiagnosticRawFailoverOnDirectSkipsTheVPNCheck(t *testing.T) {
	hits := useLocalDiagnostic(t)
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(health.Close)
	failed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := failed.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = failed.Close(); <-stopped })
	// The simulated tunnel's SOCKS handshake always fails. The direct
	// member can reach the distinct URL-test health endpoint.
	d := startDiagnosticCore(t, &model.Config{Connections: []model.Connection{
		{ID: "main", Type: model.ConnSingBox, Outbound: map[string]any{
			"type": "urltest", "mode": "failover", "url": health.URL, "outbounds": []string{"vpn", "reserve"},
		}},
		{ID: "vpn", Type: model.ConnLink, Link: "socks5://" + failed.Addr().String()},
		{ID: "reserve", Type: model.ConnSingBox, Outbound: map[string]any{"type": "direct"}},
	}})
	out, _, ok := d.eng.Outbound("main")
	group, isGroup := out.(adapter.URLTestGroup)
	if !ok || !isGroup {
		t.Fatal("raw failover group did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		if selected := group.Selected("tcp"); selected != nil && selected.Tag() == "reserve" {
			break
		}
		if _, err := group.URLTest(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("raw failover group did not select its healthy direct member")
		case <-time.After(10 * time.Millisecond):
		}
	}
	report, err := d.DiagnosticTargetIfCurrent(ctx, "main", model.ConfigRevision(d.Config()))
	if err != nil || report.Group != "main" || report.Connection != "reserve" || !report.SkippedVPN ||
		!report.CheckedAt.IsZero() || len(report.Results) != 0 || hits.Load() != 0 {
		t.Fatalf("direct reserve returned VPN readings, outbound %q, %d checks, %d requests, error %v",
			report.Connection, len(report.Results), hits.Load(), err)
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
		{"vless://a7e68fba-cd36-4079-9c4a-fa7b5c8d93a2@proxy.example.test:443", "Region a7E68fbaCd3640799C4aFa7b5c8D93a2", ""},
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

func TestDiagnosticAutomaticTargetFollowsSubscriptionSelection(t *testing.T) {
	directHits := useLocalDiagnostic(t)
	firstPort, firstHits := useLocalDiagnosticSOCKS(t)
	secondPort, secondHits := useLocalDiagnosticSOCKS(t)
	first, second := strings.Repeat("a", 32), strings.Repeat("b", 32)
	secondTag := model.ManagedTarget("main", second)
	auto := model.ManagedTarget("main", "auto")
	nodes := []subscription.Node{
		{ID: first, Name: "First region", Link: "socks5://127.0.0.1:" + strconv.Itoa(firstPort) + "#First%20region"},
		{ID: second, Name: "Second region", Link: "socks5://127.0.0.1:" + strconv.Itoa(secondPort) + "#Second%20region"},
	}
	cfg := &model.Config{
		Networks:      []model.Network{{Name: "Home", Target: auto}},
		Subscriptions: []subscription.Source{{ID: "main", Fallback: model.TargetDirect}},
	}
	cfg.Defaults()
	compiled, err := compile.Compile(compile.Input{Config: cfg, Subscriptions: map[string][]subscription.Node{"main": nodes}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := compile.RuntimeValidationConfig(compiled)
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: cfg}
	t.Cleanup(func() { _ = d.eng.Close() })
	if _, err := d.eng.Apply(raw); err != nil {
		t.Fatal(err)
	}
	state := appliedSubscription{snapshot: subscriptionSnapshot{
		Nodes: nodes, Selection: subscriptionSelection{Reason: subscriptionSwitchFallback},
		Metadata: subscription.Metadata{Title: "Office subscription"},
	}}
	d.subscriptions.states = map[string]appliedSubscription{"main": state}
	if err := d.restoreSubscriptionSelectorsLocked(compiled, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	out, _, _ := d.eng.Outbound(auto)
	group, ok := out.(adapter.OutboundGroup)
	if !ok {
		t.Fatal("automatic selector was not installed")
	}
	if selected := group.Selected("tcp"); selected == nil || selected.Tag() != model.TargetDirect {
		t.Fatal("automatic selector did not activate its direct reserve")
	}
	rev := model.ConfigRevision(d.Config())
	skipped, err := d.DiagnosticTargetIfCurrent(t.Context(), auto, rev)
	if err != nil || !skipped.SkippedVPN || skipped.Group != auto || skipped.Connection != model.TargetDirect ||
		skipped.GroupName != "Office subscription" || skipped.Reserve != model.TargetDirect ||
		!skipped.CheckedAt.IsZero() || len(skipped.Results) != 0 || skipped.Node != (DiagnosticNode{}) ||
		firstHits.Load() != 0 || secondHits.Load() != 0 || directHits.Load() != 0 {
		t.Fatalf("automatic diagnostics on reserve returned %d probes, %d candidate requests and %d reserve requests, error %v",
			len(skipped.Results), firstHits.Load()+secondHits.Load(), directHits.Load(), err)
	}
	if !d.eng.Select(auto, secondTag) {
		t.Fatal("automatic selector could not activate the second node")
	}
	state.snapshot.Selection = subscriptionSelection{Node: second, Reason: subscriptionSwitchRecovered}
	d.subscriptions.states["main"] = state
	active, err := d.DiagnosticTargetIfCurrent(t.Context(), auto, rev)
	if err != nil || active.SkippedVPN || active.Group != auto || active.Connection != secondTag || active.CheckedAt.IsZero() ||
		active.GroupName != "Office subscription" || active.Reserve != "" ||
		active.Node != (DiagnosticNode{Name: "Second region", Position: 2}) || len(active.Results) != 1 || !active.Results[0].OK ||
		firstHits.Load() != 0 || secondHits.Load() != 1 || directHits.Load() != 0 {
		t.Fatalf("automatic diagnostics did not test only the active node, first %d, second %d, reserve %d, error %v",
			firstHits.Load(), secondHits.Load(), directHits.Load(), err)
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
	// Report.Connection identifies the outbound even without a running engine.
	assertTarget := func(target, want string) {
		t.Helper()
		report, err := d.DiagnosticTargetIfCurrent(t.Context(), target, rev)
		if !errors.Is(err, ErrDiagnosticConnection) || report.Connection != want {
			t.Errorf("target %s resolved to %q, error %v, want %q", target, report.Connection, err, want)
		}
	}
	for target, want := range map[string]string{"primary": "primary", tag: tag, balance: tag} {
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
