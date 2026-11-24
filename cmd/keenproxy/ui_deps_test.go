package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/geodata"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

func TestRoutingRulesProjection(t *testing.T) {
	rules := compile.BuildProviderRules(&subscription.RoutingProfile{
		RouteOrder: "block-direct-proxy", GlobalProxy: true,
		DirectSites: []string{"domain:a.example", "full:b.example", "literal", "regexp:^c"},
		DirectIP:    []string{"geoip:private", "192.0.2.0/24"},
		ProxySites:  []string{"geosite:youtube"},
	}, nil, nil, nil)
	deps := uiDeps{daemon: routingSnapshotDaemon{rules: rules}}
	got := deps.ProviderRules()
	want := ui.RoutingRules{
		Source: "fixture", State: "partial", HasProfile: true, GlobalProxy: true,
		Rules: []ui.RoutingRule{
			{Key: "direct:literals:site", Action: "direct", Kind: "site", Source: "literals", LiteralCount: 4},
			{Key: "direct:literals:ip", Action: "direct", Kind: "ip", Source: "literals", LiteralCount: 1},
			{Key: "proxy:geosite:youtube", Action: "proxy", Kind: "site", Source: "geosite:youtube", Unavailable: "provider sent no geosite file"},
		},
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("routing projection = %+v, want %+v", got, want)
	}
}

func TestRoutingHTMLRedactsProviderRuleKeysAndLabels(t *testing.T) {
	const token = "routing-fixture-token"
	source := subscription.Source{ID: "fixture", URL: "https://provider.example/private?key=" + token, SendHWID: true}
	var hwid string
	transport := routingRoundTrip(func(r *http.Request) (*http.Response, error) {
		hwid = r.Header.Get("X-HWID")
		profile, err := json.Marshal(map[string]any{
			"Geositeurl": "https://data.example/geosite.dat",
			"ProxySites": []string{"geosite:https://other.example/?nested=" + url.QueryEscape(source.URL), "geosite:device-" + hwid},
			"BlockSites": []string{"geosite:" + source.URL},
		})
		if err != nil {
			t.Fatal(err)
		}
		header := make(http.Header)
		header.Set("routing", "happ://routing/add/"+base64.StdEncoding.EncodeToString(profile))
		return &http.Response{
			StatusCode: http.StatusOK, Header: header,
			Body: io.NopCloser(strings.NewReader("socks5://fixture.example:1080#Fixture")),
		}, nil
	})
	fetcher := subscription.NewFetcher(filepath.Join(t.TempDir(), "identity"), transport)
	result := fetcher.Fetch(t.Context(), source)
	if result.State != subscription.StateReady || result.Routing == nil || hwid == "" {
		t.Fatalf("synthetic routing fixture did not load: %s", result.State)
	}
	sites := make(map[string]geodata.Sites)
	for _, entry := range result.Routing.ProxySites {
		sites[strings.TrimPrefix(entry, "geosite:")] = geodata.Sites{Suffix: []string{"rule.example"}}
	}
	rules := compile.BuildProviderRules(result.Routing, sites, nil, nil)
	cfg := &model.Config{Subscriptions: []subscription.Source{source}}
	cfg.RouteHomeThroughSubscription(source.ID, netip.MustParsePrefix("192.0.2.0/24"))
	deps := uiDeps{daemon: routingSnapshotDaemon{rules: rules, cfg: cfg}}
	for _, role := range []ui.Role{ui.RoleManage, ui.RoleView} {
		h := ui.New(deps, ui.Options{Role: func(*http.Request) ui.Role { return role }})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/routing", nil))
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Fatalf("routing rendered HTTP %d for role %v", w.Code, role)
		}
		if strings.Contains(body, token) || strings.Contains(body, hwid) || strings.Contains(body, "provider.example") {
			t.Errorf("routing HTML for role %v disclosed subscription data", role)
		}
		if !strings.Contains(body, "[redacted]") {
			t.Errorf("routing HTML for role %v omitted its redacted label", role)
		}
		keys := regexp.MustCompile(`name="rule" value="([^"]+)"`).FindAllStringSubmatch(body, -1)
		if len(keys) != 2 || keys[0][1] == keys[1][1] {
			t.Errorf("routing HTML for role %v lost distinct switches", role)
		}
	}
}

type routingRoundTrip func(*http.Request) (*http.Response, error)

func (run routingRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return run(r) }

type routingSnapshotDaemon struct {
	managementDaemon
	rules compile.ProviderRules
	cfg   *model.Config
}

func (d routingSnapshotDaemon) ProviderRules() (compile.ProviderRules, *model.ProviderRulesSettings, daemon.ProviderRulesState) {
	return d.rules, &model.ProviderRulesSettings{Source: "fixture"}, daemon.ProviderRulesPartial
}

func (d routingSnapshotDaemon) Config() *model.Config { return d.cfg.Clone() }

func (d routingSnapshotDaemon) RoutingStatus() daemon.RoutingStatus {
	return daemon.RoutingStatus{
		Ready: true, TargetClasses: map[string]stats.TargetClass{d.cfg.Networks[0].Target: stats.TargetVPN},
	}
}

func (routingSnapshotDaemon) Subscriptions() []daemon.SubscriptionStatus { return nil }
