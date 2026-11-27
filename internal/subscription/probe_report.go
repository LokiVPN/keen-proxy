package subscription

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const (
	probeReportTimeout  = 20 * time.Second
	maxProbeReportBytes = 128 << 10
)

// ProbeResult is one route observation in the PasarGuard v1 report vocabulary.
type ProbeResult struct {
	Verdict string
	DelayMS int64
}

// ProbeReport is one batch for the delivery that advertised Probe-Report.
// Results are keyed by the share-list line that the manifest locator names.
type ProbeReport struct {
	URL     string
	Results map[int]ProbeResult
}

// probeReportURL resolves the advertised report address against the final
// HTTPS fetch URL. Another origin is allowed because CDNs in front of
// subscriptions often reject POST; the address must still be HTTPS without
// userinfo or a fragment, and an IP literal must be public. Host names are
// checked again on every dial by the report transport.
func probeReportURL(resp *http.Response) string {
	raw := strings.TrimSpace(resp.Header.Get("Probe-Report-Url"))
	if strings.TrimSpace(resp.Header.Get("Probe-Report")) != "1" || raw == "" || resp.Request == nil {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	target := resp.Request.URL.ResolveReference(ref)
	if httpsOrigin(target) == "" || target.Fragment != "" {
		return ""
	}
	if addr, err := netip.ParseAddr(target.Hostname()); err == nil && !publicProbeAddr(addr) {
		return ""
	}
	return target.String()
}

// nonPublicPrefixes are ranges outside netip's predicates that must not
// receive reports: CGNAT, "this network", benchmarking (sing-box fake IPs)
// and reserved space including broadcast.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// publicProbeAddr reports whether a report may be sent to addr.
func publicProbeAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var errProbeAddress = errors.New("probe report address is not public")

// newProbeTransport dials only public addresses. The check runs on the
// address actually dialed, after DNS resolution, so a rebinding name cannot
// reach the router or LAN. It never uses a proxy, which would dial instead.
func newProbeTransport() http.RoundTripper {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		addr, err := netip.ParseAddrPort(address)
		if err != nil || !publicProbeAddr(addr.Addr()) {
			return errProbeAddress
		}
		return nil
	}}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
}

// SendProbeReport reads the delivery manifest and posts one explicit report
// (the contract's "PasarGuard v1" format). It makes one attempt without
// redirects or retries through the public-only report transport, never the
// subscription transport. The grant in the URL is the only credential sent:
// no HWID, cookies or subscription headers reach the report origin.
func (f *Fetcher) SendProbeReport(ctx context.Context, report ProbeReport) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, probeReportTimeout)
	defer cancel()
	client := &http.Client{Transport: f.probeTransport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var manifest struct {
		Format string `json:"format"`
		Routes []struct {
			RouteID string `json:"route_id"`
			Locator []int  `json:"locator"`
		} `json:"routes"`
	}
	if err := probeExchange(ctx, client, http.MethodGet, report.URL, nil, &manifest); err != nil {
		return 0, err
	}
	// Share lists are the only format this fetcher parses; locators are lines.
	if manifest.Format != "links" && manifest.Format != "links_base64" {
		return 0, errors.New("probe manifest format is not a share list")
	}
	type server struct {
		RouteID string `json:"route_id"`
		Verdict string `json:"verdict"`
		DelayMS int64  `json:"delay_ms,omitempty"`
	}
	servers := make([]server, 0, len(manifest.Routes))
	for _, route := range manifest.Routes {
		if len(route.Locator) != 1 {
			continue
		}
		if result, ok := report.Results[route.Locator[0]]; ok {
			servers = append(servers, server{RouteID: route.RouteID, Verdict: result.Verdict, DelayMS: result.DelayMS})
		}
	}
	if len(servers) == 0 {
		return 0, nil
	}
	body, err := json.Marshal(map[string]any{"v": 1, "servers": servers})
	if err != nil {
		return 0, err
	}
	var receipt struct {
		Accepted int `json:"accepted"`
	}
	err = probeExchange(ctx, client, http.MethodPost, report.URL, body, &receipt)
	return receipt.Accepted, err
}

// probeExchange returns fixed errors without provider text or the grant URL.
func probeExchange(ctx context.Context, client *http.Client, method, target string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid probe report URL")
	}
	req.Header.Set("User-Agent", "KeenProxy/1")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("probe report request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe report endpoint returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeReportBytes+1))
	if err != nil || len(data) > maxProbeReportBytes || json.Unmarshal(data, out) != nil {
		return errors.New("probe report response is invalid")
	}
	return nil
}
