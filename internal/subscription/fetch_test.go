package subscription_test

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	vless = "vless://11111111-2222-3333-4444-555555555555@node.example:443"
	hy2   = "hysteria2://fixture-password@hy.example:443"
)

func TestValidateSource(t *testing.T) {
	for _, source := range []subscription.Source{
		{ID: "provider_1-test", URL: "https://provider.example/secure?param=%23"},
		{ID: strings.Repeat("a", 64), URL: "HTTPS://provider.example:443/secure"},
		{ID: "a", URL: "https://[2001:db8::1]:8443/secure"},
	} {
		if err := subscription.ValidateSource(source); err != nil {
			t.Fatalf("valid source rejected: %v", err)
		}
	}
	for _, source := range []subscription.Source{
		{ID: "", URL: "https://provider.example"},
		{ID: "Provider", URL: "https://provider.example"},
		{ID: "provider:alt", URL: "https://provider.example"},
		{ID: strings.Repeat("a", 65), URL: "https://provider.example"},
		{ID: "provider", URL: "http://provider.example/fixture-token"},
		{ID: "provider", URL: "https://user:fixture-token@provider.example/"},
		{ID: "provider", URL: "https://provider.example/#fixture-token"},
		{ID: "provider", URL: "https://provider.example/#"},
		{ID: "provider", URL: "https:///fixture-token"},
		{ID: "provider", URL: "https://provider.example:99999/fixture-token"},
		{ID: "provider", URL: "https://provider.example:/fixture-token"},
		{ID: "provider", URL: "https://[provider.example]/fixture-token"},
	} {
		err := subscription.ValidateSource(source)
		if err == nil || strings.Contains(err.Error(), "fixture-token") {
			t.Fatalf("wanted a privacy-safe validation error, got %v for %#v", err, source)
		}
	}
}

func TestFetchShareListAndMetadata(t *testing.T) {
	body := strings.Join([]string{
		"#profile-title: ignored body title",
		"#announce: ignored body notice",
		"#support-url: https://provider.example/body-help",
		"#profile-web-page-url: javascript:alert(1)",
		"#profile-update-interval: 200",
		"#subscription-userinfo: upload=2; download=5; total=9; expire=1798761600; ignored=6",
		"#routing-enable: 0",
		vless + "?security=tls&type=raw#First%20node",
		vless + "?type=tcp&security=tls#Duplicate",
		hy2 + "?sni=hy.example#HY2",
		"hy2://fixture-password@hy.example?sni=hy.example#HY2%20duplicate",
		"ssr://fixture-unsupported-profile",
		"vless://fixture-malformed-profile",
	}, "\r\n")
	for name, encode := range map[string]func(string) string{
		"plain":  func(s string) string { return s },
		"base64": func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
		"base64 url-safe": func(s string) string {
			encoded := base64.RawURLEncoding.EncodeToString([]byte(s))
			return encoded[:56] + "\r\n" + encoded[56:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !strings.Contains(r.UserAgent(), "KeenProxy") || !strings.Contains(r.Header.Get("Accept"), "text/plain") {
					t.Error("subscription GET did not ask for a share-list response")
				}
				w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Example \u2764")))
				w.Header().Set("Announce", "base64:"+base64.StdEncoding.EncodeToString([]byte("<b>Planned maintenance</b>\nTomorrow")))
				w.Header().Set("Support-URL", "https://provider.example/help")
				fmt.Fprint(w, " \r\n\ufeff"+encode(body)+"\r\n")
			})
			result := subscription.NewFetcher("", provider.Client().Transport).Fetch(t.Context(), sourceFor(provider.URL))
			if result.State != "ready" || result.Error != "" || result.Skipped != 2 || len(result.Nodes) != 2 {
				t.Fatalf("unexpected share-list result: %s, error %q, %d skipped, %d nodes", result.State, result.Error, result.Skipped, len(result.Nodes))
			}
			if result.Nodes[0].Name != "First node" || result.Nodes[1].Name != "HY2" || !strings.HasSuffix(result.Nodes[0].Link, "#First%20node") {
				t.Fatal("duplicate handling did not preserve the first provider label and link")
			}
			metadata := result.Metadata
			wantUsage := subscription.Usage{Upload: 2, Download: 5, Total: 9, Expire: 1798761600}
			if metadata.Title != "Example \u2764" || metadata.Announce != "<b>Planned maintenance</b>\nTomorrow" ||
				metadata.SupportURL != "https://provider.example/help" || metadata.ProfileURL != "" ||
				metadata.UpdateIntervalHours != 168 || metadata.Usage == nil || *metadata.Usage != wantUsage {
				t.Fatalf("unexpected metadata: %#v", metadata)
			}
			raw, err := json.Marshal(result)
			if err != nil || strings.Contains(string(raw), "fixture-password") || strings.Contains(string(raw), "vless://") || strings.Contains(string(raw), "routing-enable") {
				t.Fatal("public result encoding included a raw profile or an unsupported metadata field")
			}
			private, err := json.Marshal(result.Nodes)
			if err != nil || !strings.Contains(string(private), `"link":"hysteria2://`) {
				t.Fatal("private snapshot encoding lost the source link")
			}
		})
	}
}

func TestFetchStableNodeIDs(t *testing.T) {
	old := vless + "?security=tls&type=xhttp&extra=" + url.QueryEscape(`{"sessionIDTable":"hex","sessionIDLength":[8,16]}`)
	alias := vless + "?type=splithttp&extra=" + url.QueryEscape(`{"session_length":"8-16","session_table":"hex"}`) + "&security=tls"
	different := strings.Replace(alias, "11111111-2222-3333-4444-555555555555", "22222222-3333-4444-5555-666666666666", 1)
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first":
			fmt.Fprintln(w, old+"#Original")
			fmt.Fprintln(w, hy2+"#Original%20HY2")
		case "/second":
			fmt.Fprintln(w, hy2+"#New%20HY2")
			fmt.Fprintln(w, alias+"#Relabeled")
			fmt.Fprintln(w, different+"#Changed%20credential")
		}
	})
	fetcher := subscription.NewFetcher("", provider.Client().Transport)
	first := fetcher.Fetch(t.Context(), sourceFor(provider.URL+"/first"))
	second := fetcher.Fetch(t.Context(), sourceFor(provider.URL+"/second"))
	if first.State != "ready" || second.State != "ready" || len(first.Nodes) != 2 || len(second.Nodes) != 3 {
		t.Fatalf("expected parsed profiles, got %s (%d) and %s (%d)", first.State, len(first.Nodes), second.State, len(second.Nodes))
	}
	if first.Nodes[0].ID != second.Nodes[1].ID || first.Nodes[1].ID != second.Nodes[0].ID || second.Nodes[1].ID == second.Nodes[2].ID {
		t.Fatal("node identities changed on an equivalent refresh or stayed the same after a credential change")
	}
	if id, err := hex.DecodeString(first.Nodes[0].ID); err != nil || len(id) != 16 {
		t.Fatal("node identity is not a 128-bit hex digest")
	}
	node := first.Nodes[0]
	node.Link = second.Nodes[1].Link
	if !node.MatchesLink() {
		t.Fatal("equivalent profile failed its stored node ID check")
	}
	node.Link = second.Nodes[2].Link
	if node.MatchesLink() || (subscription.Node{}).MatchesLink() {
		t.Fatal("snapshot accepted an empty or mismatched node ID")
	}
}

func TestFetchProviderStatus(t *testing.T) {
	for _, test := range []struct {
		name, key, value, body, state string
		status, skipped               int
		transient                     bool
	}{
		{name: "modern quota", key: "x-hwid-max-devices-reached", value: "true", status: 200, state: "hwid_limit"},
		{name: "compat quota", key: "x-hwid-limit", value: "1", status: 200, body: vless, state: "hwid_limit"},
		{name: "missing identifier", key: "x-hwid-not-supported", value: "TRUE", status: 404, state: "hwid_required"},
		{name: "legacy quota", status: 403, body: `{"detail":"Device limit reached"}`, state: "hwid_limit"},
		{name: "legacy required", status: 403, body: `{"detail":"HWID header required"}`, state: "hwid_required"},
		{name: "legacy plain text quota", status: 403, body: "Device limit reached", state: "hwid_limit"},
		{name: "legacy generic denial", status: 403, body: `{"detail":"Denied fixture-token"}`, state: "http_error"},
		{name: "negative flag", key: "x-hwid-limit", value: "false", status: 200, body: vless, state: "ready"},
		{name: "arbitrary flag value", key: "x-hwid-limit", value: "32", status: 200, body: vless, state: "ready"},
		{name: "empty", status: 200, body: " \r\n#profile-title: Body title\n", state: "empty"},
		{name: "unsupported link", status: 200, body: "ssr://fixture-token\n", state: "unsupported", skipped: 1},
		{name: "unsupported page", status: 200, body: "<html>fixture-token</html>", state: "unsupported"},
		{name: "throttled", status: 429, body: "fixture-token", state: "http_error", transient: true},
		{name: "unavailable", status: 503, body: "fixture-token", state: "http_error", transient: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if test.key != "" {
					w.Header().Set(test.key, test.value)
				}
				w.Header().Set("Profile-Title", "Example provider")
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			})
			result := subscription.NewFetcher("", provider.Client().Transport).Fetch(t.Context(), sourceFor(provider.URL+"/fixture-token"))
			if result.State != test.state || result.Skipped != test.skipped || result.Metadata.Title != "Example provider" || result.Transient != test.transient {
				t.Fatalf("state=%s error=%q skipped=%d title=%q transient=%t", result.State, result.Error, result.Skipped, result.Metadata.Title, result.Transient)
			}
			if strings.Contains(result.Error, "fixture-token") || (test.state != "ready" && (result.Error == "" || len(result.Nodes) != 0)) {
				t.Fatal("failed attempt included private data or lacked a status diagnostic")
			}
		})
	}
}

func TestFetchHWIDPersistsAcrossURLsAndRestart(t *testing.T) {
	seen := make(chan string, 5)
	handler := func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-HWID")
		fmt.Fprintln(w, vless)
	}
	first := tlsProvider(t, handler)
	second := tlsProvider(t, handler)
	transport := trustingTransport(t, first, second)
	identity := filepath.Join(t.TempDir(), "state", "hwid.key")
	fetch := func(f *subscription.Fetcher, endpoint string, sendHWID bool) string {
		t.Helper()
		source := sourceFor(endpoint)
		source.SendHWID = sendHWID
		if result := f.Fetch(t.Context(), source); result.State != "ready" {
			t.Fatalf("subscription fetch failed: %s %s", result.State, result.Error)
		}
		return <-seen
	}
	fetcher := subscription.NewFetcher(identity, transport)
	if fetch(fetcher, first.URL+"/test-no-hwid", false) != "" {
		t.Fatal("request sent HWID before opt-in")
	}
	if _, err := os.Stat(identity); !os.IsNotExist(err) {
		t.Fatalf("state file exists before opt-in: %v", err)
	}
	id := fetch(fetcher, first.URL+"/original", true)
	if id == "" || id != fetch(fetcher, first.URL+"/rotated?token=2", true) ||
		id != fetch(subscription.NewFetcher(identity, transport), first.URL+"/after-restart", true) ||
		id == fetch(fetcher, second.URL+"/other-origin", true) {
		t.Fatal("HWID was not stable for the same origin and separate across origins")
	}
	if raw, err := hex.DecodeString(id); err != nil || len(raw) != 16 {
		t.Fatal("provider HWID is not 128-bit hexadecimal")
	}
	info, err := os.Stat(identity)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("installation identity is not privately persisted: %v", err)
	}
}

func TestFetchRedactsEchoedSubscriptionURLAndHWID(t *testing.T) {
	const (
		sourcePath   = "/fixture-source-token?token=one"
		redirectPath = "/fixture-redirect-token?token=two"
		finalPath    = "/fixture-final-token?token=three"
		fragment     = "#fixture-provider-view"
		profileURL   = "https://provider.example/help"
	)
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fixture-source-token":
			http.Redirect(w, r, redirectPath, http.StatusFound)
		case "/fixture-redirect-token":
			http.Redirect(w, r, finalPath+fragment, http.StatusFound)
		case "/fixture-final-token":
			hwid := r.Header.Get("X-HWID")
			if hwid == "" {
				t.Error("provider fixture did not receive the opted-in HWID")
			}
			originalURL := "HTTPS://" + r.Host + sourcePath
			normalizedURL := "https://" + r.Host + sourcePath
			redirectURL := "https://" + r.Host + redirectPath
			finalURL := "https://" + r.Host + finalPath
			w.Header().Set("Profile-Title", "Provider "+originalURL+" for "+hwid)
			w.Header().Set("Support-URL", "https://provider.example/ticket?subscription="+url.QueryEscape(finalURL))
			w.Header().Set("Profile-Web-Page-URL", profileURL)
			announce := "Check " + normalizedURL + ", then " + redirectURL + ", " + finalURL + " and " + finalURL + fragment + "."
			fmt.Fprintln(w, "#announce: base64:"+base64.StdEncoding.EncodeToString([]byte(announce)))
			name := "Office " + originalURL + " " + finalURL + " " + hwid + " backup"
			fmt.Fprintln(w, vless+"#"+url.PathEscape(name))
		case "/fixture-limit-token":
			w.Header().Set("X-HWID-Limit", "true")
			w.Header().Set("Profile-Web-Page-URL", profileURL+"/"+r.Header.Get("X-HWID"))
			w.Header().Set("Announce", "Device "+r.Header.Get("X-HWID")+" blocked")
		}
	})
	fetcher := subscription.NewFetcher(filepath.Join(t.TempDir(), "hwid.key"), provider.Client().Transport)
	source := sourceFor(strings.Replace(provider.URL, "https:", "HTTPS:", 1) + sourcePath)
	source.SendHWID = true
	result := fetcher.Fetch(t.Context(), source)
	if result.State != "ready" || len(result.Nodes) != 1 {
		t.Fatalf("provider fetch returned %s with %d nodes", result.State, len(result.Nodes))
	}
	if result.Metadata.Title != "Provider [redacted] for [redacted]" ||
		result.Metadata.Announce != "Check [redacted] then [redacted] [redacted] and [redacted]" ||
		result.Metadata.SupportURL != "" || result.Metadata.ProfileURL != profileURL {
		t.Fatal("provider metadata left an echoed value visible or lost benign content")
	}
	if result.Nodes[0].Name != "Office [redacted] [redacted] [redacted] backup" ||
		!strings.Contains(result.Nodes[0].Link, "fixture-final-token") {
		t.Fatal("node display redaction lost the benign label or changed the private link")
	}
	source.URL = provider.URL + "/fixture-limit-token"
	limited := fetcher.Fetch(t.Context(), source)
	if limited.State != "hwid_limit" || limited.Metadata.ProfileURL != "" || limited.Metadata.Announce != "Device [redacted] blocked" {
		t.Fatal("metadata from a device-limit response exposed the sent HWID")
	}
}

func TestFetchFiltersMetadataBySubscriptionHost(t *testing.T) {
	const distinctLink = "https://help.example/list?token=fixture%2Bvalue"
	for _, tc := range []struct {
		name, link string
		keep       bool
	}{
		{name: "other host", link: distinctLink, keep: true},
		{name: "same host account", link: "/account", keep: true},
		{name: "off-host link with an embedded subscription in its raw query", link: "https://help.example/ticket?source={origin}/list?token=fixture%20value;view=account"},
		{name: "same host path with an embedded subscription", link: "/account/{origin}/list%3Ftoken=fixture%20value"},
		{name: "same host query", link: "/account?token=fixture%2Bvalue"},
		{name: "same host fragment", link: "/account#fixture"},
		{name: "empty query", link: "/account?"},
		{name: "empty fragment", link: "/account#"},
		{name: "subscription path", link: "/l%69st"},
		{name: "nested escape in subscription path", link: "/l%2569st"},
		{name: "redirect path", link: "/redirected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := func(origin string) string {
				value := strings.ReplaceAll(tc.link, "{origin}", origin)
				if strings.HasPrefix(value, "/") {
					return origin + value
				}
				return value
			}
			provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/list" {
					http.Redirect(w, r, "/redirected?token=fixture%2Bredirect", http.StatusFound)
					return
				}
				w.Header().Set("Profile-Web-Page-URL", link("https://"+r.Host))
				fmt.Fprintln(w, vless)
			})
			source := sourceFor(provider.URL + "/list?token=fixture%20value")
			result := subscription.NewFetcher("", provider.Client().Transport).Fetch(t.Context(), source)
			if result.State != subscription.StateReady {
				t.Fatalf("expected a ready subscription, got %s", result.State)
			}
			var want string
			if tc.keep {
				want = link(provider.URL)
			}
			if result.Metadata.ProfileURL != want {
				t.Fatal("metadata URL did not follow the subscription host policy")
			}
		})
	}
}

func TestFetchRedactsNormalizedSubscriptionHosts(t *testing.T) {
	for _, tc := range []struct {
		name, host, echoedHost string
	}{
		{name: "IDNA", host: "xn--i-9bb.example", echoedHost: "%C4%B0.example:8443"},
		{name: "IPv6", host: "[2001:db8::1]", echoedHost: "[2001:0db8:0:0::1]:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ticket := "https://help.example/ticket?source=https://" + tc.echoedHost + "/other"
			transport := providerRoundTrip(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header: http.Header{
						"Announce":             {"See " + ticket + " for details"},
						"Profile-Web-Page-Url": {ticket},
					},
					Body: io.NopCloser(strings.NewReader(vless)),
				}, nil
			})
			source := sourceFor("https://" + tc.host + "/list?token=fixture")
			result := subscription.NewFetcher("", transport).Fetch(t.Context(), source)
			if result.State != subscription.StateReady {
				t.Fatalf("expected a ready subscription, got %s", result.State)
			}
			if result.Metadata.Announce != "See [redacted] for details" || result.Metadata.ProfileURL != "" {
				t.Fatal("the normalized subscription host escaped display redaction")
			}
		})
	}
}

func TestFetchRejectsUntrustedTLSAndCrossOriginRedirect(t *testing.T) {
	crossOrigin := make(chan struct{}, 1)
	destination := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		crossOrigin <- struct{}{}
		fmt.Fprintln(w, vless)
	})
	origin := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good/fixture-token":
			if r.Header.Get("X-HWID") == "" {
				t.Error("initial same-origin request did not carry the configured HWID")
			}
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/bad/fixture-token":
			http.Redirect(w, r, destination.URL+"/fixture-token", http.StatusFound)
		case "/final":
			if r.Header.Get("X-HWID") == "" || r.Referer() != "" {
				t.Error("same-origin redirect lost HWID or leaked the source URI as the referrer")
			}
			fmt.Fprintln(w, vless)
		}
	})
	identity := filepath.Join(t.TempDir(), "hwid.key")
	good := sourceFor(origin.URL + "/good/fixture-token")
	good.SendHWID = true
	if result := subscription.NewFetcher(identity, nil).Fetch(t.Context(), good); result.State != "network_error" || strings.Contains(result.Error, "fixture-token") {
		t.Fatalf("default client accepted untrusted TLS or leaked its URL: %s %q", result.State, result.Error)
	}
	fetcher := subscription.NewFetcher(identity, trustingTransport(t, origin, destination))
	if result := fetcher.Fetch(t.Context(), good); result.State != "ready" {
		t.Fatalf("safe same-origin redirect failed: %s %q", result.State, result.Error)
	}
	bad := sourceFor(origin.URL + "/bad/fixture-token")
	bad.SendHWID = true
	if result := fetcher.Fetch(t.Context(), bad); result.State != "invalid" || strings.Contains(result.Error, "fixture-token") {
		t.Fatalf("cross-origin redirect was accepted or leaked a private identifier: %s %q", result.State, result.Error)
	}
	select {
	case <-crossOrigin:
		t.Fatal("redirect destination received a request")
	default:
	}
}

func TestFetchBoundsDecompressedResponse(t *testing.T) {
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gzipBody := gzip.NewWriter(w)
		fmt.Fprintln(gzipBody, vless)
		for range 33 {
			io.WriteString(gzipBody, strings.Repeat(" ", 64<<10))
		}
		gzipBody.Close()
	})
	result := subscription.NewFetcher("", provider.Client().Transport).Fetch(t.Context(), sourceFor(provider.URL))
	if result.State != "invalid" || len(result.Nodes) != 0 {
		t.Fatalf("oversized response yielded state %s and %d nodes", result.State, len(result.Nodes))
	}
}

func TestFetchBoundsDistinctNodes(t *testing.T) {
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		for index := range 256 {
			fmt.Fprintf(w, "%s?type=ws&path=/fixture-%d#Node\n", vless, index)
		}
		fmt.Fprintln(w, vless+"?type=ws&path=/fixture-0#Duplicate")
		if r.URL.Path == "/over-limit" {
			fmt.Fprintln(w, vless+"?type=ws&path=/fixture-outside-limit")
		}
	})
	fetcher := subscription.NewFetcher("", provider.Client().Transport)
	atLimit := fetcher.Fetch(t.Context(), sourceFor(provider.URL+"/at-limit"))
	if atLimit.State != "ready" || len(atLimit.Nodes) != 256 || atLimit.Skipped != 0 {
		t.Fatalf("256 distinct nodes plus a duplicate returned %s, %d nodes and %d skipped", atLimit.State, len(atLimit.Nodes), atLimit.Skipped)
	}
	aboveLimit := fetcher.Fetch(t.Context(), sourceFor(provider.URL+"/over-limit"))
	if aboveLimit.State != "invalid" || len(aboveLimit.Nodes) != 0 || aboveLimit.Error != "Subscription response exceeds 256 distinct nodes" {
		t.Fatalf("oversized node list returned %s, %d nodes and diagnostic %q", aboveLimit.State, len(aboveLimit.Nodes), aboveLimit.Error)
	}
}

func TestFetchWaitsForOneSlotAndRespectsCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
			fmt.Fprintln(w, vless)
		}
	})
	defer close(release)
	fetcher := subscription.NewFetcher("", provider.Client().Transport)
	first := make(chan subscription.Result, 1)
	firstContext, cancelFirst := context.WithCancel(t.Context())
	defer cancelFirst()
	go func() { first <- fetcher.Fetch(firstContext, sourceFor(provider.URL+"/first")) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first fetch did not reach provider")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Millisecond)
	defer cancel()
	if result := fetcher.Fetch(ctx, sourceFor(provider.URL+"/second")); result.State != "network_error" {
		t.Fatalf("queued request returned %s", result.State)
	}
	select {
	case <-started:
		t.Fatal("second fetch reached provider while the first held the download slot")
	default:
	}
	cancelFirst()
	select {
	case result := <-first:
		if result.State != "network_error" {
			t.Fatalf("canceled request returned %s", result.State)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active fetch did not respect cancellation")
	}
}

func sourceFor(endpoint string) subscription.Source {
	return subscription.Source{ID: "provider", URL: endpoint}
}

type providerRoundTrip func(*http.Request) (*http.Response, error)

func (f providerRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func tlsProvider(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

func trustingTransport(t *testing.T, providers ...*httptest.Server) http.RoundTripper {
	t.Helper()
	roots := x509.NewCertPool()
	for _, provider := range providers {
		roots.AddCert(provider.Certificate())
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}
