package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/links"
)

const (
	maxResponseBytes = 2 << 20
	maxLegacyError   = 4 << 10
	fetchTimeout     = 15 * time.Second
	maxRedirects     = 3
	canceledDownload = "Subscription download was canceled or timed out"
)

var errRedirect = errors.New("subscription redirect rejected")

// Fetcher shares one download slot and one installation identity across sources.
// Preview and periodic refresh should use the same instance.
type Fetcher struct {
	transport http.RoundTripper
	// probeTransport carries probe reports, which may go to another origin.
	probeTransport http.RoundTripper
	identityPath   string
	slot           chan struct{}
}

// NewFetcher uses direct, certificate-verified HTTPS unless a transport is supplied.
func NewFetcher(identityPath string, transport http.RoundTripper) *Fetcher {
	if transport == nil {
		transport = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			// An idle HTTP connection can log unsolicited provider bytes.
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 64 << 10,
		}
	}
	return &Fetcher{
		transport:      transport,
		probeTransport: newProbeTransport(),
		identityPath:   identityPath,
		slot:           make(chan struct{}, 1),
	}
}

// Transport returns the direct HTTPS transport for other provider downloads,
// such as the geo files a routing profile names.
func (f *Fetcher) Transport() http.RoundTripper { return f.transport }

// SanitizeSnapshotDisplay reapplies display bounds and source redaction to
// restored metadata and names. Legacy links cannot use the same-origin
// account exception because their original redirect paths are unavailable.
// It returns the same display protection for legacy routing categories.
// A nil result means the caller must omit the cached provider text.
// Restoring a snapshot never creates an installation identity.
func (f *Fetcher) SanitizeSnapshotDisplay(source Source, metadata *Metadata, nodes []Node, linksChecked bool, fingerprint string) func(string) string {
	u, origin, err := parseSource(source)
	if err != nil {
		return nil
	}
	sensitive := sourceDisplayRedactor(u)
	sensitive.blockSameHostLinks = !linksChecked
	if source.SendHWID {
		secret, err := readIdentity(f.identityPath)
		if err != nil {
			return nil
		}
		sensitive.hwid = deriveOriginHWID(secret, origin)
		if hwidFingerprint(sensitive.hwid) != fingerprint {
			return nil
		}
	}
	metadata.Title = displayText(metadata.Title, titleLimit, sensitive)
	metadata.Announce = displayText(metadata.Announce, announceLimit, sensitive)
	metadata.SupportURL = metadataURL(metadata.SupportURL, sensitive)
	metadata.ProfileURL = metadataURL(metadata.ProfileURL, sensitive)
	for i := range nodes {
		node := &nodes[i]
		profile, err := links.Parse(node.Link)
		if err != nil {
			node.Name = fmt.Sprintf("Node %d", i+1)
			continue
		}
		node.Name = displayNodeName(profile, links.Name(node.Link), node.Name, sensitive, i+1)
	}
	return func(entry string) string { return displayRoutingCategory(entry, sensitive) }
}

func sameOriginRedirect(request *http.Request, previous []*http.Request) error {
	origin := httpsOrigin(request.URL)
	if len(previous) > maxRedirects || origin == "" || origin != httpsOrigin(previous[0].URL) {
		return errRedirect
	}
	// The source token can be in either the path or query, including on the same origin.
	request.Header.Del("Referer")
	return nil
}

// Fetch downloads and decodes one bounded share list. It never applies profiles.
func (f *Fetcher) Fetch(ctx context.Context, source Source) Result {
	uri, origin, err := parseSource(source)
	if err != nil {
		return failure(StateInvalid, err.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	select {
	case f.slot <- struct{}{}:
		defer func() { <-f.slot }()
	case <-ctx.Done():
		return failure(StateNetworkError, canceledDownload)
	}
	if ctx.Err() != nil {
		return failure(StateNetworkError, canceledDownload)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return failure(StateInvalid, "Invalid subscription request URL")
	}
	req.Header.Set("User-Agent", "KeenProxy/1")
	req.Header.Set("Accept", "text/plain, application/octet-stream")
	sensitive := sourceDisplayRedactor(req.URL)
	if source.SendHWID {
		hwid, err := originHWID(f.identityPath, origin)
		if err != nil {
			return failure(StateInvalid, "Could not load or save the installation identity")
		}
		req.Header.Set("X-HWID", hwid)
		req.Header.Set("X-Device-OS", runtime.GOOS)
		sensitive.hwid = hwid
	}
	client := http.Client{Transport: f.transport, CheckRedirect: func(request *http.Request, previous []*http.Request) error {
		if err := sameOriginRedirect(request, previous); err != nil {
			return err
		}
		sensitive.addURL(request.URL)
		return nil
	}}
	resp, err := client.Do(req)
	if errors.Is(err, errRedirect) {
		return failure(StateInvalid, "Subscription provider redirected outside the HTTPS origin or exceeded the redirect limit")
	}
	if err != nil {
		if ctx.Err() != nil {
			return failure(StateNetworkError, canceledDownload)
		}
		return failure(StateNetworkError, "Could not download the subscription")
	}
	defer resp.Body.Close()
	result := readResponse(ctx, resp, sensitive)
	result.HWIDFingerprint = hwidFingerprint(sensitive.hwid)
	if result.State == StateReady {
		result.ProbeReportURL = probeReportURL(resp)
	}
	return result
}

func readResponse(ctx context.Context, resp *http.Response, sensitive displayRedactor) Result {
	result := responseStatus(resp)
	if result.State != StateReady {
		return withHeaders(resp.Header, sensitive, result)
	}
	if resp.ContentLength > maxResponseBytes {
		return withHeaders(resp.Header, sensitive, failure(StateInvalid, "Subscription response exceeds 2 MiB"))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return withHeaders(resp.Header, sensitive, failure(StateNetworkError, "Could not read the subscription response"))
	}
	if len(data) > maxResponseBytes {
		return withHeaders(resp.Header, sensitive, failure(StateInvalid, "Subscription response exceeds 2 MiB"))
	}
	return parseShareList(ctx, resp.Header, data, sensitive)
}

func responseStatus(resp *http.Response) Result {
	if enabledHeader(resp.Header.Get("X-HWID-Max-Devices-Reached")) || enabledHeader(resp.Header.Get("X-HWID-Limit")) {
		return failure(StateHWIDLimit, "Subscription provider device limit reached")
	}
	if enabledHeader(resp.Header.Get("X-HWID-Not-Supported")) {
		return failure(StateHWIDRequired, "Subscription provider requires an HWID")
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return Result{State: StateReady}
	}
	if resp.StatusCode == http.StatusForbidden {
		switch legacyHWIDDetail(resp.Body) {
		case "device limit reached":
			return failure(StateHWIDLimit, "Subscription provider device limit reached")
		case "hwid header required":
			return failure(StateHWIDRequired, "Subscription provider requires an HWID")
		}
	}
	result := failure(StateHTTPError, fmt.Sprintf("Subscription provider returned HTTP %d", resp.StatusCode))
	result.Transient = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500
	return result
}

// Older providers describe the HWID decision in a small error body.
func legacyHWIDDetail(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, maxLegacyError+1))
	if err != nil || len(data) > maxLegacyError {
		return ""
	}
	var legacy struct{ Detail string }
	if err := json.Unmarshal(data, &legacy); err == nil {
		return strings.ToLower(strings.TrimSpace(legacy.Detail))
	}
	return strings.ToLower(strings.TrimSpace(string(data)))
}

func enabledHeader(value string) bool {
	value = strings.TrimSpace(value)
	return value == "1" || strings.EqualFold(value, "true")
}

func failure(state, message string) Result {
	return Result{State: state, Error: message, Transient: state == StateNetworkError}
}

func withHeaders(headers http.Header, sensitive displayRedactor, result Result) Result {
	result.Metadata = parseMetadata(headers, nil, sensitive)
	return result
}
