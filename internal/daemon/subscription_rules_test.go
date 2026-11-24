package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
	held     map[string]chan struct{}
	requests map[string]int
}

func newRulesProvider(t *testing.T) *rulesProvider {
	t.Helper()
	p := &rulesProvider{files: map[string][]byte{}, held: map[string]chan struct{}{}, requests: map[string]int{}}
	p.Server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.Close)
	return p
}

func (p *rulesProvider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.requests[r.URL.Path]++
	held := p.held[r.URL.Path]
	p.mu.Unlock()
	if held != nil {
		select {
		case <-held:
		case <-r.Context().Done():
			return
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
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

// hold stalls requests for path until the test ends or the client gives up.
func (p *rulesProvider) hold(t *testing.T, path string) {
	held := make(chan struct{})
	p.update(func(p *rulesProvider) { p.held[path] = held })
	t.Cleanup(func() { close(held) })
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

var (
	testGeositeData = testGeosite(map[string][]string{
		"VIDEO": {"video.example"}, "ADS": {"ads.example"}, "UNUSED": {"unused.example"},
	})
	testGeoipData = testGeoip(map[string][]string{"DIRECT": {"192.0.2.0/24"}})
)

func newRulesTestDaemon(t *testing.T) (*Daemon, *model.Config, *rulesProvider) {
	t.Helper()
	p := newRulesProvider(t)
	p.update(func(p *rulesProvider) {
		p.files["/geosite.dat"] = testGeositeData
		p.files["/geoip.dat"] = testGeoipData
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
			p.update(func(p *rulesProvider) {
				p.files["/huge/geosite.dat"] = testGeosite(map[string][]string{"VIDEO": domains})
			})
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

func TestProviderRulesApplyBoundsStalledGeoDownloads(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	p.hold(t, "/geoip.dat")
	// Apply's deadline leaves about two seconds for geo files before its headroom.
	ctx, cancel := context.WithTimeout(t.Context(), applyGeoHeadroom+2*time.Second)
	defer cancel()
	started := time.Now()
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatalf("a stalled geo file failed Apply after %v: %v", time.Since(started), err)
	}
	if waited := time.Since(started); waited > 5*time.Second {
		t.Fatalf("Apply waited %v for a stalled geo file", waited)
	}
	rules, _, ok := d.ProviderRules()
	if !ok {
		t.Fatal("rules are unavailable")
	}
	if rule := providerRule(t, rules, "direct:geoip:direct"); rule.Unavailable != "geoip file could not be downloaded" || rule.CIDR != nil {
		t.Fatalf("rule of the stalled file = %+v", rule)
	}
	if rule := providerRule(t, rules, "proxy:geosite:video"); rule.Unavailable != "" {
		t.Fatalf("rule of the downloaded file = %+v", rule)
	}
	if got := d.Subscriptions()[0].RulesError; got != "geoip file could not be downloaded" {
		t.Fatalf("rules error = %q", got)
	}
}

func TestProviderRulesApplyWithoutTimeLeavesGeoFilesToTheWorker(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	// Less than the minimum is left before the headroom.
	ctx, cancel := context.WithTimeout(t.Context(), applyGeoHeadroom+applyGeoMinimum/2)
	defer cancel()
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if n := p.count("/geosite.dat") + p.count("/geoip.dat"); n != 0 {
		t.Fatalf("Apply started %d geo downloads without time for them", n)
	}
	rules, _, ok := d.ProviderRules()
	if !ok || providerRule(t, rules, "proxy:geosite:video").Unavailable == "" || providerRule(t, rules, "direct:literals:site").Unavailable != "" {
		t.Fatalf("rules = %+v", rules)
	}
}

// claimSubscriptionRequest takes the worker's next request as if the clock
// read now plus after.
func claimSubscriptionRequest(d *Daemon, after time.Duration) *subscriptionRefresh {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nextSubscriptionRefreshLocked(time.Now().Add(after))
}

func TestProviderRulesRetryMissingGeoFilesEarly(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	p.update(func(p *rulesProvider) { delete(p.files, "/geoip.dat") })
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	subscriptionRequests := p.count("/sub")
	for i, wait := range []time.Duration{time.Minute, 2 * time.Minute} {
		if claimSubscriptionRequest(d, wait-5*time.Second) != nil {
			t.Fatalf("retry %d came before %v", i+1, wait)
		}
		request := claimSubscriptionRequest(d, wait+time.Second)
		if request == nil {
			t.Fatalf("no retry %d after %v", i+1, wait)
		}
		if i == 1 {
			p.update(func(p *rulesProvider) { p.files["/geoip.dat"] = testGeoipData })
		}
		d.runSubscriptionRequest(t.Context(), request)
	}
	requireAppliedProviderRules(t, d)
	if got := d.Subscriptions()[0].RulesError; got != "" {
		t.Fatalf("rules error after recovery = %q", got)
	}
	if p.count("/sub") != subscriptionRequests || p.count("/geosite.dat") != 1 || p.count("/geoip.dat") != 3 {
		t.Fatalf("requests: sub %d, geosite %d, geoip %d", p.count("/sub"), p.count("/geosite.dat"), p.count("/geoip.dat"))
	}
	if claimSubscriptionRequest(d, 2*time.Hour) != nil {
		t.Fatal("retries continued after the files loaded")
	}

	// Complete rules stay as last good rules, so only a failure after the
	// provider withheld them starts retries again: from one minute.
	for _, change := range []func(*rulesProvider){
		func(p *rulesProvider) { p.enable = "0" },
		func(p *rulesProvider) { p.enable = ""; delete(p.files, "/geoip.dat") },
	} {
		p.update(change)
		d.RefreshSubscription("sample")
		d.runSubscriptionRequest(t.Context(), claimSubscriptionRequest(d, 0))
	}
	if claimSubscriptionRequest(d, 55*time.Second) != nil || claimSubscriptionRequest(d, time.Minute+time.Second) == nil {
		t.Fatal("a new series of retries did not start from one minute")
	}
}

func TestProviderRulesRetryKeepsAManualRefresh(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	p.update(func(p *rulesProvider) { delete(p.files, "/geoip.dat") })
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	retry := claimSubscriptionRequest(d, time.Minute+time.Second)
	if retry == nil || !d.RefreshSubscription("sample") {
		t.Fatal("retry or manual refresh was not accepted")
	}
	d.runSubscriptionRequest(t.Context(), retry)
	refresh := claimSubscriptionRequest(d, 0)
	if refresh == nil {
		t.Fatal("a manual refresh requested during a geo file retry was lost")
	}
	subscriptionRequests := p.count("/sub")
	d.runSubscriptionRequest(t.Context(), refresh)
	if p.count("/sub") != subscriptionRequests+1 {
		t.Fatal("the manual refresh did not fetch the subscription")
	}
}

func TestProviderRulesRetryDelayDoublesUpToAnHour(t *testing.T) {
	var got []time.Duration
	for failures := 1; failures <= 9; failures++ {
		got = append(got, rulesRetryDelay(failures)/time.Minute)
	}
	if want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}; !slices.Equal(got, want) {
		t.Fatalf("retry delays in minutes = %v, want %v", got, want)
	}
}

func TestProviderRulesRetryActivationFailureWaitsForTheNextRetry(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	p.update(func(p *rulesProvider) { delete(p.files, "/geoip.dat") })
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	partial, _, _ := d.ProviderRules()
	path := d.subscriptionSnapshotPath(cfg)
	if err := os.Rename(path, path+".before"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	p.update(func(p *rulesProvider) { p.files["/geoip.dat"] = testGeoipData })
	d.runSubscriptionRequest(t.Context(), claimSubscriptionRequest(d, time.Minute+time.Second))
	if rules, _, _ := d.ProviderRules(); !reflect.DeepEqual(rules, partial) {
		t.Fatalf("rules that could not be saved were installed: %+v", rules)
	}
	if claimSubscriptionRequest(d, time.Minute) != nil || claimSubscriptionRequest(d, 2*time.Minute+time.Second) == nil {
		t.Fatal("a failed activation did not wait for the next retry")
	}
}

// ruleSetFiles lists the rule-set files of d whose names start with prefix.
func ruleSetFiles(t *testing.T, d *Daemon, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(d.opt.RuleSetDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	return names
}

// providerRuleSetWith returns the tag of the provider rule set of d whose
// file holds text, or "" when none does.
func providerRuleSetWith(t *testing.T, d *Daemon, text string) string {
	t.Helper()
	var found []string
	for _, name := range ruleSetFiles(t, d, "provider-") {
		raw, err := os.ReadFile(filepath.Join(d.opt.RuleSetDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), text) {
			found = append(found, strings.TrimSuffix(name, ".json"))
		}
	}
	if len(found) > 1 {
		t.Fatalf("%s is in several provider rule sets: %v", text, found)
	}
	if len(found) == 0 {
		return ""
	}
	return found[0]
}

func requireCompiledRuleSets(t *testing.T, d *Daemon, tags ...string) {
	t.Helper()
	d.mu.Lock()
	out, err := d.compileRuntimeLocked()
	d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range tags {
		if tag == "" || !strings.Contains(string(out.SingBox), `"`+tag+`"`) {
			t.Fatalf("the compiled configuration does not use rule set %q", tag)
		}
	}
}

func TestProviderRulesReachTheCoreAfterRestart(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	video, direct := providerRuleSetWith(t, d, `"video.example"`), providerRuleSetWith(t, d, `"192.0.2.0/24"`)
	requireCompiledRuleSets(t, d, video, direct)
	if providerRuleSetWith(t, d, `"ads.example"`) != "" {
		t.Fatal("the switched-off rule has a rule set")
	}
	// The DNS fallback sets of the two provider domain rules survive the
	// cleanup of stale sets next to the one of the Video group.
	dnsSets := ruleSetFiles(t, d, "dns-")
	d.flushDomains()
	if got := ruleSetFiles(t, d, "dns-"); len(dnsSets) != 3 || !slices.Equal(got, dnsSets) {
		t.Fatalf("DNS fallback sets %v, after cleanup %v", dnsSets, got)
	}

	p.Close()
	d.shutdown()
	for _, name := range append(ruleSetFiles(t, d, "provider-"), dnsSets...) {
		if err := os.Remove(filepath.Join(d.opt.RuleSetDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	// The restarted core starts with rule sets written from the snapshot.
	reopened := New(d.opt)
	t.Cleanup(reopened.shutdown)
	if _, err := reopened.startLocked(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := providerRuleSetWith(t, reopened, `"video.example"`); got != video {
		t.Fatalf("rule set after restart %q, want %q", got, video)
	}
	requireCompiledRuleSets(t, reopened, video, direct)
}

func TestProviderRulesRefreshRewritesRuleSets(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	video := providerRuleSetWith(t, d, `"video.example"`)
	runSubscriptionTestWorker(t, d)

	// A rule the provider adds reaches the running core without an Apply.
	p.useProfile("/geosite.dat", "/geoip.dat", "geosite:unused")
	refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.State == subscription.StateReady })
	requireCompiledRuleSets(t, d, video, providerRuleSetWith(t, d, `"unused.example"`))

	// New data for a rule replaces its file under the same tag, which the
	// running core watches.
	p.update(func(p *rulesProvider) {
		p.files["/v2/geosite.dat"] = testGeosite(map[string][]string{
			"VIDEO": {"video2.example"}, "ADS": {"ads.example"}, "UNUSED": {"unused.example"},
		})
	})
	p.useProfile("/v2/geosite.dat", "/geoip.dat", "geosite:unused")
	refreshProviderRules(t, d, func(got SubscriptionStatus) bool { return got.State == subscription.StateReady })
	if got := providerRuleSetWith(t, d, `"video2.example"`); got != video {
		t.Fatalf("updated rule set %q, want %q", got, video)
	}
}

// A daemon started from a reset v0.10 configuration has provider_rules set and
// a snapshot without rules: the worker evaluates them on its first pass instead
// of waiting for the subscription's refresh interval.
func TestProviderRulesEvaluatedOnTheFirstWorkerPassAfterStartup(t *testing.T) {
	d, cfg, p := newRulesTestDaemon(t)
	settings := cfg.ProviderRules
	cfg.ProviderRules = nil
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	d.shutdown()

	opt := d.opt
	opt.Config = cfg.Clone()
	opt.Config.ProviderRules = settings
	reopened := New(opt)
	t.Cleanup(reopened.shutdown)
	reopened.subscriptions.fetcher = d.subscriptions.fetcher
	if _, err := reopened.startLocked(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := reopened.ProviderRules(); ok {
		t.Fatal("rules existed before the worker ran")
	}
	runSubscriptionTestWorker(t, reopened)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, _, ok := reopened.ProviderRules(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rules were not evaluated on the first worker pass (geosite requests: %d)", p.count("/geosite.dat"))
		}
	}
	requireAppliedProviderRules(t, reopened)
}
