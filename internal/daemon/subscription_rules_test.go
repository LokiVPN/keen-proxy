package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// rulesProvider is an HTTPS provider that serves one subscription with a Happ
// routing header and the profile's dat files, counting requests by path.
type rulesProvider struct {
	*httptest.Server
	mu       sync.Mutex
	routing  string
	enable   string
	files    map[string][]byte
	requests map[string]int
}

func newRulesProvider(t *testing.T) *rulesProvider {
	t.Helper()
	p := &rulesProvider{files: map[string][]byte{}, requests: map[string]int{}}
	p.Server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.Close)
	return p
}

func (p *rulesProvider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests[r.URL.Path]++
	if r.URL.Path == "/sub" {
		if p.routing != "" {
			w.Header().Set("routing", p.routing)
		}
		if p.enable != "" {
			w.Header().Set("routing-enable", p.enable)
		}
		_, _ = io.WriteString(w, subscriptionFirst+"\n"+subscriptionSecond)
		return
	}
	if data, ok := p.files[r.URL.Path]; ok {
		_, _ = w.Write(data)
		return
	}
	http.NotFound(w, r)
}

func (p *rulesProvider) update(change func(*rulesProvider)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(p)
}

func (p *rulesProvider) count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests[path]
}

// useProfile serves a profile whose geo files are the given paths of p.
// Extra entries are appended to its direct sites.
func (p *rulesProvider) useProfile(geosite, geoip string, extra ...string) {
	direct, _ := json.Marshal(append([]string{"domain:direct.example", "geosite:private"}, extra...))
	profile := fmt.Sprintf(`{"Name": "Test rules", "GlobalProxy": "false", "Geositeurl": %q, "Geoipurl": %q,
		"DirectSites": %s, "DirectIp": ["geoip:private", "geoip:direct"],
		"ProxySites": ["geosite:video"], "BlockSites": ["geosite:ads"]}`, p.URL+geosite, p.URL+geoip, direct)
	p.update(func(p *rulesProvider) {
		p.routing = "happ://routing/add/" + base64.StdEncoding.EncodeToString([]byte(profile))
	})
}

func appendMessage(b []byte, num protowire.Number, message []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, message)
}

// testGeosite encodes a geosite.dat with domain-suffix entries per category.
func testGeosite(categories map[string][]string) []byte {
	var list []byte
	for code, domains := range categories {
		entry := appendMessage(nil, 1, []byte(code))
		for _, domain := range domains {
			d := protowire.AppendTag(nil, 1, protowire.VarintType)
			d = protowire.AppendVarint(d, 2) // domain suffix
			entry = appendMessage(entry, 2, appendMessage(d, 2, []byte(domain)))
		}
		list = appendMessage(list, 1, entry)
	}
	return list
}

// testGeoip encodes a geoip.dat with prefixes per tag.
func testGeoip(tags map[string][]string) []byte {
	var list []byte
	for code, prefixes := range tags {
		entry := appendMessage(nil, 1, []byte(code))
		for _, value := range prefixes {
			prefix := netip.MustParsePrefix(value)
			c := appendMessage(nil, 1, prefix.Addr().AsSlice())
			c = protowire.AppendTag(c, 2, protowire.VarintType)
			entry = appendMessage(entry, 2, protowire.AppendVarint(c, uint64(prefix.Bits())))
		}
		list = appendMessage(list, 1, entry)
	}
	return list
}

var testGeositeData = testGeosite(map[string][]string{
	"VIDEO": {"video.example"}, "ADS": {"ads.example"}, "UNUSED": {"unused.example"},
})

func newRulesTestDaemon(t *testing.T) (*Daemon, *model.Config, *rulesProvider) {
	t.Helper()
	p := newRulesProvider(t)
	p.update(func(p *rulesProvider) {
		p.files["/geosite.dat"] = testGeositeData
		p.files["/geoip.dat"] = testGeoip(map[string][]string{"DIRECT": {"192.0.2.0/24"}})
	})
	p.useProfile("/geosite.dat", "/geoip.dat")
	d, cfg := newSubscriptionTestDaemon(t, p.Client().Transport)
	cfg.Subscriptions = []subscription.Source{{ID: "sample", URL: p.URL + "/sub"}}
	cfg.ProviderRules = &model.ProviderRulesSettings{Source: "sample", Disabled: []string{"block:geosite:ads"}}
	return d, cfg, p
}

func providerRule(t *testing.T, rules compile.ProviderRules, key string) compile.ProviderRule {
	t.Helper()
	for _, rule := range rules.Rules {
		if rule.Key == key {
			return rule
		}
	}
	t.Fatalf("rule %q is missing from %+v", key, rules.Rules)
	return compile.ProviderRule{}
}

func requireAppliedProviderRules(t *testing.T, d *Daemon) compile.ProviderRules {
	t.Helper()
	rules, settings, ok := d.ProviderRules()
	if !ok || settings == nil || settings.Source != "sample" || !slices.Equal(settings.Disabled, []string{"block:geosite:ads"}) {
		t.Fatalf("provider rules unavailable: %v %+v", ok, settings)
	}
	if rules.Name != "Test rules" || rules.GlobalProxy || rules.RouteOrder != "block-direct-proxy" {
		t.Fatalf("profile settings were not copied: %+v", rules)
	}
	for key, want := range map[string][]string{
		"proxy:geosite:video":  {"video.example"},
		"block:geosite:ads":    {"ads.example"},
		"direct:literals:site": {"direct.example"},
	} {
		if rule := providerRule(t, rules, key); rule.Unavailable != "" || !slices.Equal(rule.Suffix, want) {
			t.Fatalf("rule %s = %+v", key, rule)
		}
	}
	if rule := providerRule(t, rules, "direct:geoip:direct"); rule.Unavailable != "" || !slices.Equal(rule.CIDR, []string{"192.0.2.0/24"}) {
		t.Fatalf("geoip rule = %+v", rule)
	}
	return rules
}

func refreshProviderRules(t *testing.T, d *Daemon, check func(SubscriptionStatus) bool) SubscriptionStatus {
	t.Helper()
	before := d.Subscriptions()[0].LastAttempt
	if !d.RefreshSubscription("sample") {
		t.Fatal("refresh was not accepted")
	}
	return awaitSubscriptionStatus(t, d, func(got SubscriptionStatus) bool {
		return got.LastAttempt != nil && (before == nil || got.LastAttempt.After(*before)) && check(got)
	})
}

func TestProviderRulesAppliedAndRestoredWithoutProvider(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	rules := requireAppliedProviderRules(t, d)
	if p.count("/geosite.dat") != 1 || p.count("/geoip.dat") != 1 {
		t.Fatalf("dat downloads: geosite %d, geoip %d", p.count("/geosite.dat"), p.count("/geoip.dat"))
	}
	if status := d.Subscriptions()[0]; status.RulesError != "" {
		t.Fatalf("unexpected rules error %q", status.RulesError)
	}

	p.Close()
	d.shutdown()
	reopened := New(d.opt)
	t.Cleanup(reopened.shutdown)
	if _, err := reopened.startLocked(t.Context()); err != nil {
		t.Fatal(err)
	}
	restored, _, ok := reopened.ProviderRules()
	if !ok || !reflect.DeepEqual(restored, rules) {
		t.Fatalf("rules did not survive a restart:\n got %+v\nwant %+v", restored, rules)
	}
}

func TestProviderRulesPreviewDownloadsNothingAndRefreshReusesDatFiles(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	if preview := d.PreviewSubscription(t.Context(), cfg.Subscriptions[0]); preview.State != subscription.StateReady {
		t.Fatalf("preview failed: %+v", preview)
	}
	if n := p.count("/geosite.dat") + p.count("/geoip.dat"); n != 0 {
		t.Fatalf("preview downloaded %d dat files", n)
	}
	if _, _, ok := d.ProviderRules(); ok {
		t.Fatal("preview produced provider rules")
	}
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if p.count("/sub") != 1 {
		t.Fatalf("Apply did not reuse the preview, requests=%d", p.count("/sub"))
	}
	rules := requireAppliedProviderRules(t, d)

	runSubscriptionTestWorker(t, d)
	refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.State == subscription.StateReady })
	if p.count("/sub") != 2 || p.count("/geosite.dat") != 1 || p.count("/geoip.dat") != 1 {
		t.Fatalf("refresh requests: sub %d, geosite %d, geoip %d", p.count("/sub"), p.count("/geosite.dat"), p.count("/geoip.dat"))
	}
	if again, _, ok := d.ProviderRules(); !ok || !reflect.DeepEqual(again, rules) {
		t.Fatalf("reused rules changed: %+v", again)
	}

	// A newly referenced category needs the file again, even at the same URL.
	p.useProfile("/geosite.dat", "/geoip.dat", "geosite:unused")
	refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.State == subscription.StateReady })
	if p.count("/geosite.dat") != 2 || p.count("/geoip.dat") != 1 {
		t.Fatalf("dat downloads: geosite %d, geoip %d", p.count("/geosite.dat"), p.count("/geoip.dat"))
	}
	rules, _, _ = d.ProviderRules()
	if rule := providerRule(t, rules, "direct:geosite:unused"); rule.Unavailable != "" || !slices.Equal(rule.Suffix, []string{"unused.example"}) {
		t.Fatalf("new category rule = %+v", rule)
	}
}

func TestProviderRulesKeepLastGoodRulesOnFailures(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	good := requireAppliedProviderRules(t, d)
	runSubscriptionTestWorker(t, d)
	for _, tc := range []struct {
		name, reason string
		change       func()
	}{
		{"download", "geosite file could not be downloaded", func() { p.useProfile("/moved/geosite.dat", "/geoip.dat") }},
		{"malformed dat", "geosite file could not be read", func() {
			p.update(func(p *rulesProvider) { p.files["/bad/geosite.dat"] = []byte{0xff, 0xff} })
			p.useProfile("/bad/geosite.dat", "/geoip.dat")
		}},
		{"oversized dat", "geosite file is larger than 16 MiB", func() {
			p.update(func(p *rulesProvider) { p.files["/big/geosite.dat"] = make([]byte, 16<<20+1) })
			p.useProfile("/big/geosite.dat", "/geoip.dat")
		}},
		{"extraction limit", "geosite data exceeds the extraction limit", func() {
			domains := make([]string, 100001)
			for i := range domains {
				domains[i] = fmt.Sprintf("d%d.example", i)
			}
			p.update(func(p *rulesProvider) { p.files["/huge/geosite.dat"] = testGeosite(map[string][]string{"VIDEO": domains}) })
			p.useProfile("/huge/geosite.dat", "/geoip.dat")
		}},
		{"malformed profile", "The provider routing profile could not be read", func() {
			p.update(func(p *rulesProvider) { p.routing = "happ://routing/add/!!!" })
		}},
		{"recovered", "", func() { p.useProfile("/geosite.dat", "/geoip.dat") }},
	} {
		tc.change()
		refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.RulesError == tc.reason })
		if rules, _, ok := d.ProviderRules(); !ok || !reflect.DeepEqual(rules, good) {
			t.Fatalf("%s: last good rules were not kept: %+v", tc.name, rules)
		}
	}
	if p.count("/geosite.dat") != 1 || p.count("/geoip.dat") != 1 {
		t.Fatalf("unchanged dat files were downloaded again: geosite %d, geoip %d", p.count("/geosite.dat"), p.count("/geoip.dat"))
	}
}

func TestProviderRulesFirstFailureLeavesAffectedRulesUnavailable(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	p.update(func(p *rulesProvider) { delete(p.files, "/geosite.dat") })
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	rules, _, ok := d.ProviderRules()
	if !ok {
		t.Fatal("rules without a geosite file are unavailable")
	}
	for _, key := range []string{"proxy:geosite:video", "block:geosite:ads"} {
		if rule := providerRule(t, rules, key); rule.Unavailable != "geosite file could not be downloaded" || rule.Suffix != nil {
			t.Fatalf("rule %s = %+v", key, rule)
		}
	}
	if rule := providerRule(t, rules, "direct:geoip:direct"); rule.Unavailable != "" || len(rule.CIDR) != 1 {
		t.Fatalf("rule from the downloaded file = %+v", rule)
	}
	if status := d.Subscriptions()[0]; status.RulesError != "geosite file could not be downloaded" {
		t.Fatalf("rules error = %q", status.RulesError)
	}

	// Rules built while a file failed are not the last good rules: a profile
	// change applies even though the same file fails again.
	runSubscriptionTestWorker(t, d)
	p.useProfile("/geosite.dat", "/geoip.dat", "domain:new.example")
	refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.State == subscription.StateReady })
	rules, _, _ = d.ProviderRules()
	if rule := providerRule(t, rules, "direct:literals:site"); !slices.Equal(rule.Suffix, []string{"direct.example", "new.example"}) {
		t.Fatalf("partial rules were kept instead of rebuilt: %+v", rule)
	}

	// The next refresh downloads only the file that failed.
	p.update(func(p *rulesProvider) { p.files["/geosite.dat"] = testGeositeData })
	p.useProfile("/geosite.dat", "/geoip.dat")
	refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.RulesError == "" })
	requireAppliedProviderRules(t, d)
	if p.count("/geosite.dat") != 3 || p.count("/geoip.dat") != 1 {
		t.Fatalf("dat downloads: geosite %d, geoip %d", p.count("/geosite.dat"), p.count("/geoip.dat"))
	}
}

func TestProviderRulesDroppedWhenProviderWithholdsThem(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	requireAppliedProviderRules(t, d)
	p.update(func(p *rulesProvider) { p.enable = "0" })
	runSubscriptionTestWorker(t, d)
	status := refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.State == subscription.StateReady })
	if _, settings, ok := d.ProviderRules(); ok || settings == nil || status.RulesError != "" {
		t.Fatalf("withheld rules: ok %v, settings %+v, error %q", ok, settings, status.RulesError)
	}
}

func TestProviderRulesFollowTheSettings(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	settings := cfg.ProviderRules
	cfg.ProviderRules = nil
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, got, ok := d.ProviderRules(); ok || got != nil || p.count("/geosite.dat") != 0 {
		t.Fatalf("rules without settings: ok %v, settings %+v", ok, got)
	}

	// Turning rules on for a running subscription does not wait for its schedule.
	runSubscriptionTestWorker(t, d)
	on := cfg.Clone()
	on.ProviderRules = settings
	if err := d.Apply(t.Context(), on); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, _, ok := d.ProviderRules(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("provider rules were not built after they were turned on")
		}
	}
	requireAppliedProviderRules(t, d)

	// Turning them off drops the rules from the saved snapshot.
	off := on.Clone()
	off.ProviderRules = nil
	if err := d.Apply(t.Context(), off); err != nil {
		t.Fatal(err)
	}
	if _, got, ok := d.ProviderRules(); ok || got != nil {
		t.Fatalf("rules after turning them off: ok %v, settings %+v", ok, got)
	}
	raw, err := os.ReadFile(d.subscriptionSnapshotPath(off))
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &saved); err != nil || len(saved) != 1 {
		t.Fatalf("snapshot: %v, %s", err, raw)
	}
	for _, snapshot := range saved {
		if _, ok := snapshot["rules"]; ok {
			t.Fatalf("snapshot keeps rules that were turned off: %s", raw)
		}
	}
}
