package daemon

import (
	"cmp"
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

	"github.com/ordo-systems/keen-proxy/internal/connectionimport"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	M "github.com/sagernet/sing/common/metadata"
)

// DiagnosticResult reports one connectivity or transfer check with elapsed milliseconds.
type DiagnosticResult struct {
	Kind    string
	OK      bool
	Checked time.Time
	Latency int64
	Bytes   int64
	Error   string
}

// DiagnosticReport records the outbound and any completed probes for one check.
type DiagnosticReport struct {
	Connection string
	Results    []DiagnosticResult
	Group      string // group whose selected leaf is Connection
	GroupName  string // captured display name for a subscription group
	Reserve    string // configured reserve target used by the subscription
	SkippedVPN bool   // a reserve, direct, or block leaf was selected
	Node       DiagnosticNode
	CheckedAt  time.Time
}

// DiagnosticNode projects a node and its subscription title observed together.
// A private node name is blank and its position supplies a generic label.
type DiagnosticNode struct {
	Name, SubscriptionTitle string
	Position                int
}

// ErrDiagnosticConnection means the requested profile is absent from applied runtime state.
var ErrDiagnosticConnection = errors.New("connection is not applied")

// ErrDiagnosticNotRouting means the core is stopped or traffic interception is paused.
var ErrDiagnosticNotRouting = errors.New("KeenProxy is not routing traffic right now")

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

// DiagnosticTargetIfCurrent checks the applied target at the page's revision.
// It observes selection and recorded health without changing them.
func (d *Daemon) DiagnosticTargetIfCurrent(ctx context.Context, target, revision string) (DiagnosticReport, error) {
	d.mu.Lock()
	routing := d.diagnosticRoutingLocked()
	d.mu.Unlock()
	if !routing {
		return DiagnosticReport{}, ErrDiagnosticNotRouting
	}
	release, err := acquireDiagnosticSlot(ctx)
	if err != nil {
		return DiagnosticReport{}, err
	}
	defer release()
	d.mu.Lock()
	// An Apply can stop or pause routing while this check waits for a slot.
	if !d.diagnosticRoutingLocked() {
		d.mu.Unlock()
		return DiagnosticReport{}, ErrDiagnosticNotRouting
	}
	if !d.matchesConfigRevisionLocked(revision) {
		d.mu.Unlock()
		return DiagnosticReport{}, model.ErrConfigChanged
	}
	report := d.diagnosticRouteLocked(target)
	if report.SkippedVPN {
		d.mu.Unlock()
		return report, nil
	}
	tag := report.Connection
	if tag == "" {
		d.mu.Unlock()
		return DiagnosticReport{}, ErrDiagnosticConnection
	}
	out, engineContext, skipped, err := d.eng.DiagnosticLeaf(tag, d.diagnosticReserveLocked)
	var node subscription.Node
	var position int
	var title string
	if out != nil {
		node, position, title = d.diagnosticNodeLocked(out.Tag())
	}
	d.mu.Unlock()
	if err != nil {
		return report, err
	}
	if out == nil {
		return report, ErrDiagnosticConnection
	}
	report.Connection = out.Tag()
	if report.Group == "" && report.Connection != tag {
		report.Group = tag
	}
	report.Node = diagnosticNode(node, position, title)
	report.SkippedVPN = skipped
	if skipped {
		return report, nil
	}
	report.CheckedAt = time.Now()
	report.Results = diagnosticProfileChecks(ctx, engineContext, out.DialContext)
	return report, nil
}

// diagnosticRoutingLocked accounts for pause mode, which keeps the core alive.
func (d *Daemon) diagnosticRoutingLocked() bool {
	return d.eng.Running() && d.cfg != nil && !d.cfg.Paused
}

// DiagnosticNode reads the same protected display label used by the report.
func (d *Daemon) DiagnosticNode(tag string) DiagnosticNode {
	d.mu.Lock()
	node, position, title := d.diagnosticNodeLocked(tag)
	d.mu.Unlock()
	return diagnosticNode(node, position, title)
}

func (d *Daemon) diagnosticNodeLocked(tag string) (subscription.Node, int, string) {
	if id, node, managed := model.ParseManagedTarget(tag); managed {
		state := d.subscriptions.states[id]
		for index, entry := range state.snapshot.Nodes {
			if entry.ID == node {
				return entry, index + 1, diagnosticSubscriptionTitle(state)
			}
		}
	}
	return subscription.Node{}, 0, ""
}

func diagnosticNode(node subscription.Node, position int, title string) DiagnosticNode {
	return DiagnosticNode{Name: connectionimport.SafeLinkLabel(node.Link, node.Name), Position: position, SubscriptionTitle: title}
}

// diagnosticReserveLocked identifies a configured reserve from the actual
// selected group member. Raw groups have no separately designated reserve.
func (d *Daemon) diagnosticReserveLocked(group, member string) bool {
	for _, chain := range d.chains {
		if chain.Tag == group {
			return member != chain.ID
		}
	}
	for _, selector := range d.subscriptions.selectors {
		if selector.Tag == group {
			return !slices.Contains(selector.Candidates, member)
		}
	}
	return slices.ContainsFunc(d.cfg.Connections, func(c model.Connection) bool {
		return c.ID == group && c.Disabled
	})
}

// diagnosticRouteLocked takes the route observation before any diagnostic dial.
func (d *Daemon) diagnosticRouteLocked(target string) DiagnosticReport {
	if source, node, managed := model.ParseManagedTarget(target); managed {
		switch {
		case node == "auto":
			return d.diagnosticAutomaticLocked(source, target)
		case model.IsSubscriptionBalance(node):
			member, onReserve := d.eng.DiagnosticBalancePath(target)
			if onReserve {
				return d.diagnosticSubscriptionReserveLocked(source, d.diagnosticGroupLocked(source, target), member)
			}
			return DiagnosticReport{Connection: member}
		case slices.Contains(d.subscriptions.members, target):
			return DiagnosticReport{Connection: target}
		default:
			return d.diagnosticSubscriptionReserveLocked(source, d.diagnosticGroupLocked(source, target), d.targetAliases[target])
		}
	}
	if target == model.TargetDirect || slices.ContainsFunc(d.cfg.Connections, func(c model.Connection) bool {
		return c.ID == target && !c.Disabled
	}) {
		return DiagnosticReport{Connection: target}
	}
	return DiagnosticReport{}
}

// diagnosticAutomaticLocked uses the committed selection even when a
// candidate has recovered and is still waiting to leave the reserve.
func (d *Daemon) diagnosticAutomaticLocked(source, target string) DiagnosticReport {
	state := d.subscriptions.states[source]
	selection := state.snapshot.Selection
	report := d.diagnosticGroupLocked(source, target)
	// With no catalog the compiler routes directly to the reserve or block.
	inactive := d.targetAliases[target]
	for _, selector := range d.subscriptions.selectors {
		if selector.Tag != target {
			continue
		}
		if selection.Node != "" {
			active := model.ManagedTarget(source, selection.Node)
			if slices.Contains(selector.Candidates, active) {
				report.Connection = active
			}
			return report
		}
		inactive = model.TargetBlock
		if selection.Reason == subscriptionSwitchFallback && selector.Fallback != "" {
			inactive = selector.Fallback
		}
		break
	}
	return d.diagnosticSubscriptionReserveLocked(source, report, inactive)
}

func (d *Daemon) diagnosticGroupLocked(source, target string) DiagnosticReport {
	return DiagnosticReport{
		Group: target, GroupName: diagnosticSubscriptionTitle(d.subscriptions.states[source]),
	}
}

func diagnosticSubscriptionTitle(state appliedSubscription) string {
	return cmp.Or(state.attempt.result.Metadata.Title, state.snapshot.Metadata.Title)
}

func (d *Daemon) diagnosticSubscriptionReserveLocked(source string, report DiagnosticReport, inactive string) DiagnosticReport {
	if inactive == "" {
		return report
	}
	report.Connection, report.SkippedVPN = inactive, true
	for _, sub := range d.cfg.Subscriptions {
		if sub.ID == source && cmp.Or(d.targetAliases[sub.Fallback], sub.Fallback) == inactive {
			report.Reserve = sub.Fallback
			break
		}
	}
	return report
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
