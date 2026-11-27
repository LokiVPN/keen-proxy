package subscription_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestFetchProbeReportHeaders(t *testing.T) {
	const origin = "https://example.com"
	for _, tc := range []struct {
		name, flag, url, path, want string
	}{
		{"relative", "1", "./_probe/grant/report", "/sub/fixture-token", origin + "/sub/_probe/grant/report"},
		{"format suffix", "1", "../_probe/grant/report", "/sub/fixture-token/links", origin + "/sub/_probe/grant/report"},
		{"other public origin", "1", "https://collector.example:8443/r/grant?x=1", "/sub/fixture-token", "https://collector.example:8443/r/grant?x=1"},
		{"public IP literal", "1", "https://203.0.113.7/r", "/sub/fixture-token", "https://203.0.113.7/r"},
		{"off", "0", "./_probe/grant/report", "/sub/fixture-token", ""},
		{"absent", "", "", "/sub/fixture-token", ""},
		{"missing address", "1", "", "/sub/fixture-token", ""},
		{"plain HTTP", "1", "http://collector.example/report", "/sub/fixture-token", ""},
		{"userinfo", "1", "https://user:pass@collector.example/report", "/sub/fixture-token", ""},
		{"fragment", "1", "https://collector.example/report#x", "/sub/fixture-token", ""},
		{"loopback", "1", "https://127.0.0.1/report", "/sub/fixture-token", ""},
		{"mapped loopback", "1", "https://[::ffff:127.0.0.1]/report", "/sub/fixture-token", ""},
		{"private", "1", "https://192.168.1.1/report", "/sub/fixture-token", ""},
		{"link-local", "1", "https://169.254.169.254/report", "/sub/fixture-token", ""},
		{"CGNAT", "1", "https://100.64.0.1/report", "/sub/fixture-token", ""},
		{"IPv6 unique local", "1", "https://[fd00::1]/report", "/sub/fixture-token", ""},
		{"multicast", "1", "https://224.0.0.1/report", "/sub/fixture-token", ""},
		{"unspecified", "1", "https://0.0.0.0/report", "/sub/fixture-token", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.flag != "" {
					w.Header().Set("Probe-Report", tc.flag)
					w.Header().Set("Probe-Report-Url", tc.url)
				}
				fmt.Fprint(w, vless+"?security=tls#Node")
			})
			result := subscription.NewFetcher("", hostTransport(t, provider)).Fetch(t.Context(), sourceFor(origin+tc.path+"?q=1"))
			if result.State != "ready" || result.ProbeReportURL != tc.want {
				t.Fatalf("got %s %q, want %q", result.State, result.ProbeReportURL, tc.want)
			}
		})
	}
}

// hostTransport serves any HTTPS host from provider, whose test certificate
// is valid for example.com, so relative report URLs resolve to a public name.
func hostTransport(t *testing.T, provider *httptest.Server) http.RoundTripper {
	t.Helper()
	transport := provider.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, provider.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

// TestSendProbeReportDialsOnlyPublicAddresses checks the production report
// transport: names resolving to loopback are refused at dial time, after DNS,
// before any TCP connection is made.
func TestSendProbeReportDialsOnlyPublicAddresses(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	for _, host := range []string{"127.0.0.1", "localhost"} {
		report := subscription.ProbeReport{URL: fmt.Sprintf("https://%s:%d/r/grant", host, port), Results: map[int]subscription.ProbeResult{0: {Verdict: "ok"}}}
		_, err := subscription.NewFetcher("", nil).SendProbeReport(t.Context(), report)
		if err == nil || strings.Contains(err.Error(), "grant") {
			t.Fatalf("%s: wanted a fixed error, got %v", host, err)
		}
	}
	if len(accepted) != 0 {
		t.Fatalf("report transport connected to loopback %d times", len(accepted))
	}
}

func TestSendProbeReport(t *testing.T) {
	routeA, routeB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var posted []byte
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"X-Hwid", "X-Device-Os", "Authorization", "Cookie", "Referer"} {
			if r.Header.Get(name) != "" {
				t.Errorf("report carried %s", name)
			}
		}
		if r.URL.Path != "/sub/_probe/grant/report" {
			t.Errorf("unexpected report request %s %s", r.Method, r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			fmt.Fprintf(w, `{"format":"links_base64","routes":[{"route_id":%q,"locator":[0]},{"route_id":%q,"locator":[2]},{"route_id":"c","locator":[0,1]}]}`, routeA, routeB)
		case http.MethodPost:
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("report is not JSON")
			}
			posted, _ = io.ReadAll(r.Body)
			fmt.Fprint(w, `{"accepted":2}`)
		}
	})
	fetcher := subscription.NewFetcher("", nil)
	subscription.UseProbeTransport(fetcher, provider.Client().Transport)
	report := subscription.ProbeReport{URL: provider.URL + "/sub/_probe/grant/report", Results: map[int]subscription.ProbeResult{
		0: {Verdict: "ok", DelayMS: 120},
		2: {Verdict: "timeout"},
		5: {Verdict: "ok"},
	}}
	accepted, err := fetcher.SendProbeReport(t.Context(), report)
	if err != nil || accepted != 2 {
		t.Fatalf("send: %d, %v", accepted, err)
	}
	var got map[string]any
	if err := json.Unmarshal(posted, &got); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`{"servers":[{"delay_ms":120,"route_id":%q,"verdict":"ok"},{"route_id":%q,"verdict":"timeout"}],"v":1}`, routeA, routeB)
	if raw, _ := json.Marshal(got); string(raw) != want {
		t.Fatalf("posted %s\nwant   %s", raw, want)
	}
}

func TestSendProbeReportFailsClosed(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"disabled": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"detail":"probe_off"}`, http.StatusForbidden)
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://collector.example/", http.StatusFound)
		},
		"clash":     func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"format":"clash","routes":[]}`) },
		"malformed": func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `<html>`) },
	} {
		t.Run(name, func(t *testing.T) {
			provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("report was posted without a usable manifest")
				}
				handler(w, r)
			})
			report := subscription.ProbeReport{URL: provider.URL + "/_probe/grant/report", Results: map[int]subscription.ProbeResult{0: {Verdict: "ok"}}}
			fetcher := subscription.NewFetcher("", nil)
			subscription.UseProbeTransport(fetcher, provider.Client().Transport)
			_, err := fetcher.SendProbeReport(t.Context(), report)
			if err == nil || strings.Contains(err.Error(), "grant") {
				t.Fatalf("wanted a fixed error, got %v", err)
			}
		})
	}
}
