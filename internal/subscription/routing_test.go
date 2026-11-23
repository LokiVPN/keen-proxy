package subscription_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func encodeProfile(profile string) string {
	return base64.StdEncoding.EncodeToString([]byte(profile))
}

func routingLink(profile string) string { return "happ://routing/add/" + encodeProfile(profile) }

func fixtureProfile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/routing_profile.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseRoutingLinkRealProfile(t *testing.T) {
	profile, err := subscription.ParseRoutingLink(routingLink(fixtureProfile(t)))
	if err != nil || profile == nil {
		t.Fatalf("profile rejected: %v", err)
	}
	if profile.Name != "RoscomVPN" || !profile.GlobalProxy || profile.RouteOrder != "block-direct-proxy" || profile.DomainStrategy != "IPIfNonMatch" {
		t.Fatalf("unexpected scalars: %#v", profile)
	}
	if len(profile.DirectSites) != 16 || len(profile.DirectIP) != 2 || len(profile.ProxySites) != 5 || len(profile.BlockSites) != 3 || len(profile.ProxyIP) != 0 || len(profile.BlockIP) != 0 {
		t.Fatalf("unexpected list sizes: %#v", profile)
	}
	if profile.DirectSites[0] != "domain:remotedesktop.google.com" || profile.ProxySites[4] != "geosite:telegram" {
		t.Fatal("list order was not preserved")
	}
	if !strings.HasPrefix(profile.GeositeURL, "https://cdn.jsdelivr.net/") || !strings.HasSuffix(profile.GeositeURL, "geosite.dat") ||
		!strings.HasPrefix(profile.GeoipURL, "https://cdn.jsdelivr.net/") || !strings.HasSuffix(profile.GeoipURL, "geoip.dat") {
		t.Fatalf("unexpected dat URLs: %q %q", profile.GeositeURL, profile.GeoipURL)
	}
}

func TestParseRoutingLinkEncodings(t *testing.T) {
	raw := `{"Name":"ab?>>","DirectSites":["geosite:ru"]}`
	for name, encoded := range map[string]string{
		"standard":          base64.StdEncoding.EncodeToString([]byte(raw)),
		"standard unpadded": base64.RawStdEncoding.EncodeToString([]byte(raw)),
		"url-safe":          base64.URLEncoding.EncodeToString([]byte(raw)),
		"url-safe unpadded": base64.RawURLEncoding.EncodeToString([]byte(raw)),
	} {
		for _, verb := range []string{"add", "onadd"} {
			profile, err := subscription.ParseRoutingLink("happ://routing/" + verb + "/" + encoded)
			if err != nil || profile == nil || profile.Name != "ab?>>" || !slices.Equal(profile.DirectSites, []string{"geosite:ru"}) {
				t.Fatalf("%s/%s: %#v, %v", name, verb, profile, err)
			}
		}
	}
}

func TestParseRoutingLinkOff(t *testing.T) {
	profile, err := subscription.ParseRoutingLink("happ://routing/off")
	if profile != nil || err != nil {
		t.Fatalf("off must mean no provider rules, got %#v, %v", profile, err)
	}
}

func TestParseRoutingLinkGlobalProxy(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"GlobalProxy":true}`:      true,
		`{"GlobalProxy":false}`:     false,
		`{"GlobalProxy":"true"}`:    true,
		`{"GlobalProxy":" False "}`: false,
		`{"GlobalProxy":"FALSE"}`:   false,
		`{}`:                        true,
		`{"GlobalProxy":"maybe"}`:   true,
		`{"GlobalProxy":3}`:         true,
		`{"GlobalProxy":null}`:      true,
	} {
		profile, err := subscription.ParseRoutingLink(routingLink(raw))
		if err != nil || profile.GlobalProxy != want {
			t.Fatalf("%s: got %#v, %v", raw, profile, err)
		}
	}
}

func TestParseRoutingLinkRouteOrderAndStrategy(t *testing.T) {
	for raw, want := range map[string]string{
		`{"RouteOrder":"proxy-direct-block"}`:   "proxy-direct-block",
		`{"RouteOrder":"direct-block-proxy"}`:   "direct-block-proxy",
		`{}`:                                    "block-direct-proxy",
		`{"RouteOrder":"proxy-proxy-block"}`:    "block-direct-proxy",
		`{"RouteOrder":"block-direct"}`:         "block-direct-proxy",
		`{"RouteOrder":"block-direct-proxy-x"}`: "block-direct-proxy",
		`{"RouteOrder":"Block-Direct-Proxy"}`:   "block-direct-proxy",
	} {
		profile, err := subscription.ParseRoutingLink(routingLink(raw))
		if err != nil || profile.RouteOrder != want {
			t.Fatalf("%s: got %#v, %v", raw, profile, err)
		}
	}
	for raw, want := range map[string]string{
		`{"DomainStrategy":"AsIs"}`:         "AsIs",
		`{"DomainStrategy":"IPIfNonMatch"}`: "IPIfNonMatch",
		`{"DomainStrategy":"IPOnDemand"}`:   "IPOnDemand",
		`{"DomainStrategy":"ipifnonmatch"}`: "",
		`{"DomainStrategy":"Other"}`:        "",
		`{}`:                                "",
	} {
		profile, err := subscription.ParseRoutingLink(routingLink(raw))
		if err != nil || profile.DomainStrategy != want {
			t.Fatalf("%s: got %#v, %v", raw, profile, err)
		}
	}
}

func TestParseRoutingLinkDropsUnsafeDatURLs(t *testing.T) {
	long := "https://cdn.example/" + strings.Repeat("a", 2100)
	for _, bad := range []string{
		"http://cdn.example/geosite.dat",
		"ftp://cdn.example/geosite.dat",
		"file:///etc/passwd",
		"//cdn.example/geosite.dat",
		"/geosite.dat",
		"https:///geosite.dat",
		"https://user:pw@cdn.example/geosite.dat",
		"https://cdn.example:/geosite.dat",
		long,
	} {
		raw := fmt.Sprintf(`{"Name":"kept","Geositeurl":%q,"Geoipurl":%q,"ProxySites":["geosite:x"]}`, bad, bad)
		profile, err := subscription.ParseRoutingLink(routingLink(raw))
		if err != nil || profile.GeositeURL != "" || profile.GeoipURL != "" || profile.Name != "kept" || len(profile.ProxySites) != 1 {
			t.Fatalf("%.40s: got %#v, %v", bad, profile, err)
		}
	}
	profile, err := subscription.ParseRoutingLink(routingLink(`{"Geositeurl":"https://cdn.example/a.dat","Geoipurl":"HTTPS://cdn.example/b.dat"}`))
	if err != nil || profile.GeositeURL == "" || profile.GeoipURL == "" {
		t.Fatalf("valid https URLs dropped: %#v, %v", profile, err)
	}
}

func TestParseRoutingLinkListsAndUnknownFields(t *testing.T) {
	raw := `{"DirectSites":[" geosite:a ","","  ","geosite:b"],"BlockIp":["geoip:x"],"DnsHosts":{"a":"b"},"FakeDNS":"true","RemoteDNSIP":"8.8.8.8","Extra":[1,2]}`
	profile, err := subscription.ParseRoutingLink(routingLink(raw))
	if err != nil || !slices.Equal(profile.DirectSites, []string{"geosite:a", "geosite:b"}) || !slices.Equal(profile.BlockIP, []string{"geoip:x"}) {
		t.Fatalf("got %#v, %v", profile, err)
	}
}

func TestParseRoutingLinkSanitizesName(t *testing.T) {
	profile, err := subscription.ParseRoutingLink(routingLink(`{"Name":"  Fancy\u0000 \u0007name` + strings.Repeat("x", 400) + `"}`))
	if err != nil || strings.ContainsAny(profile.Name, "\x00\x07") || !strings.HasPrefix(profile.Name, "Fancy name") || len([]rune(profile.Name)) > 128 {
		t.Fatalf("name not sanitized: %q, %v", profile.Name, err)
	}
}

func TestParseRoutingLinkRejectsMalformedWithFixedErrors(t *testing.T) {
	huge := `{"Name":"` + strings.Repeat("a", 256<<10) + `"}`
	justOver := `{"Name":"` + strings.Repeat("a", 256<<10-len(`{"Name":""}`)+1) + `"}`
	justUnder := `{"Name":"` + strings.Repeat("a", 256<<10-len(`{"Name":""}`)) + `"}`
	for name, link := range map[string]string{
		"empty payload":     "happ://routing/add/",
		"not base64":        "happ://routing/add/!!!secret-provider-text!!!",
		"not json":          routingLink("secret-provider-text"),
		"wrong json type":   routingLink(`["secret-provider-text"]`),
		"wrong field type":  routingLink(`{"DirectSites":"secret-provider-text"}`),
		"unknown verb":      "happ://routing/remove/" + encodeProfile(`{}`),
		"not a routing URL": "https://example.com/" + encodeProfile(`{}`),
		"oversize decoded":  routingLink(huge),
		"one byte over":     routingLink(justOver),
		"oversize encoded":  "happ://routing/add/" + strings.Repeat("A", 2<<20),
	} {
		profile, err := subscription.ParseRoutingLink(link)
		if profile != nil || err == nil || strings.Contains(err.Error(), "secret-provider-text") || len(err.Error()) > 120 {
			t.Fatalf("%s: got %#v, %v", name, profile, err)
		}
	}
	if profile, err := subscription.ParseRoutingLink(routingLink(justUnder)); err != nil || profile == nil {
		t.Fatalf("a profile at the limit must parse: %v", err)
	}
}

func fetchRouting(t *testing.T, headers map[string]string, body string) subscription.Result {
	t.Helper()
	provider := tlsProvider(t, func(w http.ResponseWriter, r *http.Request) {
		for name, value := range headers {
			w.Header().Set(name, value)
		}
		fmt.Fprint(w, body)
	})
	return subscription.NewFetcher("", provider.Client().Transport).Fetch(t.Context(), sourceFor(provider.URL))
}

func TestFetchRoutingFromHeader(t *testing.T) {
	result := fetchRouting(t, map[string]string{"Routing": routingLink(`{"Name":"Header"}`)}, vless+"#One\n")
	if result.State != "ready" || result.Routing == nil || result.Routing.Name != "Header" || result.RoutingError != "" {
		t.Fatalf("unexpected result: %s %#v %q", result.State, result.Routing, result.RoutingError)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "Header") || strings.Contains(strings.ToLower(string(raw)), "routing") {
		t.Fatal("public encoding exposed the routing profile")
	}
}

func TestFetchRoutingFromBodyLine(t *testing.T) {
	for _, verb := range []string{"add", "onadd"} {
		line := "happ://routing/" + verb + "/" + encodeProfile(`{"Name":"Body"}`)
		for name, body := range map[string]string{
			"plain":  "#profile-title: x\n" + line + "\n" + vless + "#One\n",
			"base64": base64.StdEncoding.EncodeToString([]byte(vless + "#One\n" + line + "\n")),
		} {
			result := fetchRouting(t, nil, body)
			if result.State != "ready" || result.Skipped != 0 || len(result.Nodes) != 1 || result.Routing == nil || result.Routing.Name != "Body" {
				t.Fatalf("%s/%s: %s skipped=%d nodes=%d routing=%#v", verb, name, result.State, result.Skipped, len(result.Nodes), result.Routing)
			}
		}
	}
}

func TestFetchRoutingHeaderWinsOverBody(t *testing.T) {
	body := "happ://routing/add/" + encodeProfile(`{"Name":"Body"}`) + "\n" + vless + "#One\n"
	result := fetchRouting(t, map[string]string{"Routing": routingLink(`{"Name":"Header"}`)}, body)
	if result.Routing == nil || result.Routing.Name != "Header" {
		t.Fatalf("header must win: %#v", result.Routing)
	}
	// An invalid header does not fall back to the body line.
	result = fetchRouting(t, map[string]string{"Routing": "happ://routing/add/@@@"}, body)
	if result.Routing != nil || result.RoutingError == "" {
		t.Fatalf("invalid header must not fall back: %#v %q", result.Routing, result.RoutingError)
	}
	// An empty header leaves the decision to the body.
	result = fetchRouting(t, map[string]string{"Routing": "  "}, body)
	if result.Routing == nil || result.Routing.Name != "Body" {
		t.Fatalf("empty header must defer to the body: %#v", result.Routing)
	}
}

func TestFetchRoutingOffAndAbsent(t *testing.T) {
	for name, result := range map[string]subscription.Result{
		"off header": fetchRouting(t, map[string]string{"Routing": "happ://routing/off"}, vless+"#One\n"),
		"off body":   fetchRouting(t, nil, "happ://routing/off\n"+vless+"#One\n"),
		"absent":     fetchRouting(t, nil, vless+"#One\n"),
	} {
		if result.State != "ready" || result.Routing != nil || result.RoutingError != "" || result.Skipped != 0 {
			t.Fatalf("%s: %s %#v %q skipped=%d", name, result.State, result.Routing, result.RoutingError, result.Skipped)
		}
	}
}

func TestFetchRoutingEnableSwitch(t *testing.T) {
	link := routingLink(`{"Name":"P"}`)
	for _, tc := range []struct {
		name    string
		headers map[string]string
		comment string
		want    bool
	}{
		{"header 0", map[string]string{"Routing": link, "Routing-Enable": "0"}, "", false},
		{"header false", map[string]string{"Routing": link, "Routing-Enable": " False "}, "", false},
		{"header junk", map[string]string{"Routing": link, "Routing-Enable": "nope"}, "", false},
		{"header 1", map[string]string{"Routing": link, "Routing-Enable": "1"}, "", true},
		{"header TRUE", map[string]string{"Routing": link, "Routing-Enable": "TRUE"}, "", true},
		{"header empty", map[string]string{"Routing": link, "Routing-Enable": ""}, "", true},
		{"comment 0", map[string]string{"Routing": link}, "#routing-enable: 0", false},
		{"comment 1", map[string]string{"Routing": link}, "#routing-enable: 1", true},
		{"header wins over comment", map[string]string{"Routing": link, "Routing-Enable": "1"}, "#routing-enable: 0", true},
		{"header off wins over comment", map[string]string{"Routing": link, "Routing-Enable": "0"}, "#routing-enable: 1", false},
	} {
		result := fetchRouting(t, tc.headers, tc.comment+"\n"+vless+"#One\n")
		if (result.Routing != nil) != tc.want || result.RoutingError != "" || result.State != "ready" {
			t.Fatalf("%s: %#v %q", tc.name, result.Routing, result.RoutingError)
		}
	}
	// A disabled switch also hides a malformed profile: nothing is reported.
	result := fetchRouting(t, map[string]string{"Routing": "happ://routing/add/@@@", "Routing-Enable": "0"}, vless+"#One\n")
	if result.Routing != nil || result.RoutingError != "" {
		t.Fatalf("disabled switch must withhold the error too: %q", result.RoutingError)
	}
}

func TestFetchRoutingMalformedReportsFixedError(t *testing.T) {
	result := fetchRouting(t, map[string]string{"Routing": routingLink("secret-provider-text")}, vless+"#One\n")
	if result.State != "ready" || len(result.Nodes) != 1 || result.Routing != nil || result.RoutingError == "" || strings.Contains(result.RoutingError, "secret-provider-text") {
		t.Fatalf("unexpected result: %s %#v %q", result.State, result.Routing, result.RoutingError)
	}
}
