package subscription_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestFetchProbeReportHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, flag, url, path, want string
	}{
		{"relative", "1", "./_probe/grant/report", "/sub/fixture-token", "/sub/_probe/grant/report"},
		{"format suffix", "1", "../_probe/grant/report", "/sub/fixture-token/links", "/sub/_probe/grant/report"},
		{"off", "0", "./_probe/grant/report", "/sub/fixture-token", ""},
		{"absent", "", "", "/sub/fixture-token", ""},
		{"missing address", "1", "", "/sub/fixture-token", ""},
		{"other origin", "1", "https://collector.example/report", "/sub/fixture-token", ""},
		{"plain HTTP", "1", "http://provider.example/report", "/sub/fixture-token", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.flag != "" {
					w.Header().Set("Probe-Report", tc.flag)
					w.Header().Set("Probe-Report-Url", tc.url)
				}
				fmt.Fprint(w, vless+"?security=tls#Node")
			})
			result := subscription.NewFetcher("", provider.Client().Transport).Fetch(t.Context(), sourceFor(provider.URL+tc.path+"?q=1"))
			want := ""
			if tc.want != "" {
				want = provider.URL + tc.want
			}
			if result.State != "ready" || result.ProbeReportURL != want {
				t.Fatalf("got %s %q, want %q", result.State, result.ProbeReportURL, want)
			}
		})
	}
}

func TestFetchNodeLinesMatchManifestLocators(t *testing.T) {
	// Locators count nonblank, noncomment lines, including unsupported ones.
	body := strings.Join([]string{"#profile-title: x", vless + "?security=tls#A", "", "ssr://fixture-unsupported", hy2 + "?sni=hy.example#B"}, "\n")
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
	result := subscription.NewFetcher("", provider.Client().Transport).Fetch(t.Context(), sourceFor(provider.URL))
	if len(result.Nodes) != 2 || result.Nodes[0].Line != 0 || result.Nodes[1].Line != 2 {
		t.Fatalf("unexpected node lines: %+v", result.Nodes)
	}
}

func TestSendProbeReport(t *testing.T) {
	routeA, routeB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var posted []byte
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sub/_probe/grant/report" || r.Header.Get("X-HWID") != "" {
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
	fetcher := subscription.NewFetcher("", provider.Client().Transport)
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
			_, err := subscription.NewFetcher("", provider.Client().Transport).SendProbeReport(t.Context(), report)
			if err == nil || strings.Contains(err.Error(), "grant") {
				t.Fatalf("wanted a fixed error, got %v", err)
			}
		})
	}
}
