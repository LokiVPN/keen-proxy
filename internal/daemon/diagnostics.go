package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/connectionimport"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	M "github.com/sagernet/sing/common/metadata"
)

// DiagnosticResult reports one connectivity or transfer check with elapsed milliseconds.
type DiagnosticResult struct {
	Kind    string    `json:"kind"`
	OK      bool      `json:"ok"`
	Checked time.Time `json:"checked"`
	Latency int64     `json:"latency_ms"`
	Bytes   int64     `json:"bytes,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// DiagnosticReport groups checks performed through one applied connection profile.
type DiagnosticReport struct {
	Connection string             `json:"connection"`
	Results    []DiagnosticResult `json:"results"`
	Node       DiagnosticNode     `json:"-"`
	CheckedAt  time.Time          `json:"-"`
}

// DiagnosticNode projects one subscription member from the applied catalog.
// A private name is blank and the position supplies its generic display label.
type DiagnosticNode struct {
	Name     string
	Position int
}

// ErrDiagnosticConnection means the requested profile is absent from applied runtime state.
var ErrDiagnosticConnection = errors.New("connection is not applied")
var diagnosticSlots = make(chan struct{}, 2)
var errDiagnosticDNS = errors.New("diagnostic DNS lookup failed")

const (
	diagnosticTimeout  = 8 * time.Second
	diagnosticHTTPSURL = "https://www.gstatic.com/generate_204"
)

// acquireDiagnosticSlot bounds concurrent reports and returns a release function.
func acquireDiagnosticSlot(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case diagnosticSlots <- struct{}{}:
		return func() { <-diagnosticSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// DiagnosticChecks dials the actual profile, never its failover selector, and
// does not update periodic health, configuration or route selection.
func (d *Daemon) DiagnosticChecks(ctx context.Context, id string) (DiagnosticReport, error) {
	report := DiagnosticReport{Connection: id}
	cfg := d.Config()
	if cfg == nil || !slices.ContainsFunc(cfg.Connections, func(c model.Connection) bool { return c.ID == id && !c.Disabled }) {
		return report, ErrDiagnosticConnection
	}
	release, err := acquireDiagnosticSlot(ctx)
	if err != nil {
		return report, err
	}
	defer release()
	out, engineContext, ok := d.eng.Outbound(id)
	if !ok {
		return report, ErrDiagnosticConnection
	}
	report.Results = diagnosticProfileChecks(ctx, engineContext, out.DialContext)
	return report, nil
}

// DiagnosticTargetIfCurrent checks the primary outbound of an applied target
// against the same revision the page displayed. It leaves selection and
// recorded health untouched.
func (d *Daemon) DiagnosticTargetIfCurrent(ctx context.Context, target, revision string) (DiagnosticReport, error) {
	release, err := acquireDiagnosticSlot(ctx)
	if err != nil {
		return DiagnosticReport{}, err
	}
	defer release()
	d.mu.Lock()
	if !d.matchesConfigRevisionLocked(revision) {
		d.mu.Unlock()
		return DiagnosticReport{}, model.ErrConfigChanged
	}
	tag := d.diagnosticOutboundLocked(target)
	if tag == "" {
		d.mu.Unlock()
		return DiagnosticReport{}, ErrDiagnosticConnection
	}
	out, engineContext, err := d.eng.DiagnosticLeaf(tag, d.diagnosticReserveLocked)
	var node subscription.Node
	var position int
	if out != nil {
		node, position = d.diagnosticNodeLocked(out.Tag())
	}
	d.mu.Unlock()
	report := DiagnosticReport{Connection: tag}
	if err != nil {
		return report, err
	}
	if out == nil {
		return report, ErrDiagnosticConnection
	}
	report.Connection = out.Tag()
	report.Node = diagnosticNode(node, position)
	report.CheckedAt = time.Now()
	report.Results = diagnosticProfileChecks(ctx, engineContext, out.DialContext)
	return report, nil
}

// DiagnosticNode reads the same protected display label used by the report.
func (d *Daemon) DiagnosticNode(tag string) DiagnosticNode {
	d.mu.Lock()
	node, position := d.diagnosticNodeLocked(tag)
	d.mu.Unlock()
	return diagnosticNode(node, position)
}

func (d *Daemon) diagnosticNodeLocked(tag string) (subscription.Node, int) {
	if id, node, managed := model.ParseManagedTarget(tag); managed {
		for index, entry := range d.subscriptions.states[id].snapshot.Nodes {
			if entry.ID == node {
				return entry, index + 1
			}
		}
	}
	return subscription.Node{}, 0
}

func diagnosticNode(node subscription.Node, position int) DiagnosticNode {
	return DiagnosticNode{connectionimport.SafeLinkLabel(node.Link, node.Name), position}
}

// A nested routing group must never unwrap an installed reserve relay.
func (d *Daemon) diagnosticReserveLocked(tag string) bool {
	if _, node, managed := model.ParseManagedTarget(tag); managed {
		return node == "auto" || model.IsSubscriptionBalance(node)
	}
	return slices.ContainsFunc(d.cfg.Connections, func(c model.Connection) bool {
		return c.ID == tag && c.Disabled
	}) || slices.ContainsFunc(d.chains, func(chain compile.FailoverChain) bool { return chain.Tag == tag })
}

// diagnosticOutboundLocked bypasses the compiler's reserve aliases. For a
// managed policy, choose one activated subscription node for all three checks.
func (d *Daemon) diagnosticOutboundLocked(target string) string {
	if source, node, managed := model.ParseManagedTarget(target); managed {
		switch {
		case node == "auto":
			for _, selector := range d.subscriptions.selectors {
				if selector.Tag != target || len(selector.Candidates) == 0 {
					continue
				}
				active := model.ManagedTarget(source, d.subscriptions.states[source].snapshot.Selection.Node)
				if slices.Contains(selector.Candidates, active) {
					return active
				}
				// A policy on reserve has no active node. Probe its first
				// configured candidate even if prior health is unavailable.
				return selector.Candidates[0]
			}
		case model.IsSubscriptionBalance(node):
			for _, balance := range d.subscriptions.balances {
				if balance.Tag != target || len(balance.Candidates) == 0 {
					continue
				}
				for _, tag := range balance.Candidates {
					if h := d.health[tag]; h != nil && h.known && h.ok {
						return tag
					}
				}
				return balance.Candidates[0]
			}
		case slices.Contains(d.subscriptions.members, target):
			return target
		}
		return ""
	}
	if target == model.TargetDirect || slices.ContainsFunc(d.cfg.Connections, func(c model.Connection) bool {
		return c.ID == target && !c.Disabled
	}) {
		return target
	}
	return ""
}

func diagnosticProfileChecks(ctx, engineContext context.Context, dial profileDial) []DiagnosticResult {
	transport := &http.Transport{DialContext: diagnosticDialer(engineContext, dial), DisableKeepAlives: true, ResponseHeaderTimeout: diagnosticTimeout, TLSHandshakeTimeout: diagnosticTimeout, DisableCompression: true}
	defer transport.CloseIdleConnections()
	return runDiagnosticChecks(ctx, &http.Client{Transport: transport, Timeout: diagnosticTimeout})
}

// profileDial opens a connection through one specific applied engine outbound.
type profileDial func(context.Context, string, M.Socksaddr) (net.Conn, error)

// diagnosticTarget resolves an HTTP destination through the local IPv4 resolver.
func diagnosticTarget(ctx context.Context, address string) (M.Socksaddr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return M.Socksaddr{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return M.Socksaddr{}, err
	}
	// Control-plane DNS is explicit; these checks do not certify DNS leakage.
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return M.Socksaddr{}, errDiagnosticDNS
	}
	return M.SocksaddrFrom(ips[0].Unmap(), uint16(port)), nil
}

// diagnosticDialer combines engine services with request cancellation and releases
// context resources when the connection closes.
func diagnosticDialer(engineContext context.Context, dial profileDial) func(context.Context, string, string) (net.Conn, error) {
	return func(requestContext context.Context, network, address string) (net.Conn, error) {
		target, err := diagnosticTarget(requestContext, address)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(engineContext)
		stop := context.AfterFunc(requestContext, cancel)
		cleanup := func() { stop(); cancel() }
		conn, err := dial(ctx, network, target)
		if err != nil {
			cleanup()
			return nil, err
		}
		return &diagnosticConn{Conn: conn, cleanup: cleanup}, nil
	}
}

// diagnosticTest specifies a probe URL and optional exact transfer length.
type diagnosticTest struct {
	kind, url string
	bytes     int64
}

var diagnosticTests = []diagnosticTest{
	{"http", "http://connectivitycheck.gstatic.com/generate_204", 0},
	{"https", diagnosticHTTPSURL, 0},
	{"transfer", "https://speed.cloudflare.com/__down?bytes=65536", 65536},
}

// runDiagnosticChecks runs probes sequentially with redirects disabled.
func runDiagnosticChecks(ctx context.Context, original *http.Client) []DiagnosticResult {
	client := *original
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	results := make([]DiagnosticResult, 0, len(diagnosticTests))
	for _, test := range diagnosticTests {
		results = append(results, diagnosticRequest(ctx, &client, test))
	}
	return results
}
func requestDiagnostic(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(request)
}

// diagnosticResponse requires a successful HTTP status and, for transfers, an
// exact bounded byte count. It always closes the response body.
func diagnosticResponse(response *http.Response, want int64) (int64, string, error) {
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		reason := fmt.Sprintf("HTTP %d", response.StatusCode)
		return 0, reason, errors.New(reason)
	}
	if want == 0 {
		return 0, "", nil
	}
	count, err := io.Copy(io.Discard, io.LimitReader(response.Body, want+1))
	if err == nil && count != want {
		return count, "unexpected response length", errors.New("unexpected response length")
	}
	return count, "", err
}
func diagnosticNetworkError(ctx context.Context, cause error) string {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	var op *net.OpError
	switch {
	case ctx.Err() == context.DeadlineExceeded || errors.Is(cause, context.DeadlineExceeded):
		return "check timed out"
	case ctx.Err() == context.Canceled || errors.Is(cause, context.Canceled):
		return "check cancelled"
	case errors.Is(cause, errDiagnosticDNS) || errors.As(cause, &dns):
		return "DNS lookup failed"
	case errors.As(cause, &cert) || errors.As(cause, &record) || errors.As(cause, &alert):
		return "TLS check failed"
	case errors.As(cause, &op) || errors.Is(cause, io.EOF) || errors.Is(cause, io.ErrUnexpectedEOF):
		return "connection check failed"
	default:
		return "network, DNS or TLS check failed"
	}
}

// diagnosticRequest enforces one probe deadline and returns sanitized failure details.
func diagnosticRequest(ctx context.Context, client *http.Client, test diagnosticTest) DiagnosticResult {
	result := DiagnosticResult{Kind: test.kind, Checked: time.Now()}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, diagnosticTimeout)
	defer cancel()
	response, err := requestDiagnostic(ctx, client, test.url)
	if err == nil {
		result.Bytes, result.Error, err = diagnosticResponse(response, test.bytes)
	}
	result.Latency = time.Since(start).Milliseconds()
	result.OK = err == nil
	// Never expose raw engine errors: they may contain profile credentials.
	if err != nil && result.Error == "" {
		result.Error = diagnosticNetworkError(ctx, err)
	}
	return result
}

// diagnosticConn couples a transport connection to its request-context cleanup.
type diagnosticConn struct {
	net.Conn
	cleanup func()
}

// Close releases the socket and detaches the request cancellation callback.
func (c *diagnosticConn) Close() error { defer c.cleanup(); return c.Conn.Close() }
