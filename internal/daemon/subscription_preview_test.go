package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestSubscriptionPreviewDetailsProjectsPrivateRouting(t *testing.T) {
	const sourceURL = "https://PROVIDER.example:443/l%69st?token=synthetic%20key%27tail&tag=one&tag=two&blank"
	const equivalentURL = "https://provider.example/list?blank=&tag=one&tag=two&token=synthetic+key'tail"
	const aliasedHostURL = "http://%70ROVIDER.example:8443/other?token=synthetic%20key%27tail"
	const embeddedURL = "https://help.example/ticket?source=https://provider.example/list?token=fixture"
	const encodedURL = "https://help.example/ticket?source=http%253A%252F%252F%2570ROVIDER%252Eexample%253A8443%252Fother&progress=100%"
	const requestURI = "/l%2569st?token=synthetic+key'tail&tag=one&tag=two&blank"
	const supportURL = "https://help.example/ticket?source=provider.example-help&view=account%2Bdetails"
	const datURL = "https://provider.example/data/geosite.dat"
	var calls int
	var hwid string
	provider := diagnosticTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.String() != sourceURL {
			t.Error("subscription preview requested another URL")
			return nil, errors.New("unexpected request")
		}
		hwid = req.Header.Get("X-HWID")
		profile := map[string]any{
			"Name":        "<profile> " + equivalentURL,
			"GlobalProxy": false,
			"Geositeurl":  datURL,
			"DirectSites": []string{"geosite:ru@news", "geosite:ru@news", "domain:literal-direct.example"},
			"DirectIp":    []string{"geoip:ru"},
			"ProxySites":  []string{"geosite:<rule>", "geosite:" + hwid, "geosite:" + strings.Repeat("x", 4096)},
			"BlockIp":     []string{"geoip:private", "198.51.100.0/24", "geoip:a", "geoip:b", "geoip:c", "geoip:d", "geoip:e", "geoip:f", "geoip:g", "geoip:h"},
		}
		raw, err := json.Marshal(profile)
		if err != nil {
			return nil, err
		}
		headers := make(http.Header)
		headers.Set("routing", "happ://routing/add/"+base64.StdEncoding.EncodeToString(raw))
		headers.Set("profile-title", "Provider "+equivalentURL+" for review")
		headers.Set("announce", strings.Join([]string{"100% ready", equivalentURL, aliasedHostURL, embeddedURL, encodedURL, requestURI, hwid, supportURL}, " "))
		headers.Set("profile-web-page-url", embeddedURL+";view=account")
		headers.Set("support-url", supportURL)
		node, _, _ := strings.Cut(subscriptionFirst, "#")
		body := node + "#" + url.PathEscape("Provider "+equivalentURL)
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	initial := cfg.Clone()
	initial.Subscriptions, initial.Groups = nil, nil
	if err := d.Apply(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	rev := model.ConfigRevision(d.Config())
	source := subscription.Source{ID: "sample", URL: sourceURL, SendHWID: true}
	details := d.PreviewSubscriptionDetails(t.Context(), source)
	summary := details.Routing
	if details.Status.State != subscription.StateReady || len(details.Status.Nodes) != 1 ||
		summary == nil || details.Status.RulesState != ProviderRulesPending || details.PreviewID == 0 || hwid == "" {
		t.Fatal("expected a ready preview, a parsed summary and a device identity")
	}
	if calls != 1 || len(d.Subscriptions()) != 0 || model.ConfigRevision(d.Config()) != rev {
		t.Fatal("preview fetched geodata or changed the applied catalog")
	}
	if summary.Name != "<profile> [redacted]" ||
		details.Status.Metadata.Title != "Provider [redacted] for review" ||
		details.Status.Nodes[0].Name != "Provider [redacted]" {
		t.Error("a provider-host URL escaped redaction or surrounding text was lost")
	}
	if details.Status.Metadata.Announce != "100% ready [redacted] [redacted] [redacted] [redacted] [redacted] [redacted] "+supportURL {
		t.Error("the announcement leaked an embedded or schemeless URL or lost an unrelated link")
	}
	if details.Status.Metadata.ProfileURL != "" || details.Status.Metadata.SupportURL != supportURL {
		t.Error("the preview did not suppress the embedded subscription while keeping the unrelated link")
	}
	if summary.GlobalProxy ||
		summary.Direct.Sites.Count != 3 || !slices.Equal(summary.Direct.Sites.Categories, []string{"ru@news"}) ||
		summary.Direct.IP.Count != 1 || !slices.Equal(summary.Direct.IP.Categories, []string{"ru"}) ||
		summary.Proxy.Sites.Count != 3 || !slices.Equal(summary.Proxy.Sites.Categories, []string{"<rule>", "[redacted]", strings.Repeat("x", 64)}) ||
		summary.Block.IP.Count != 10 || len(summary.Block.IP.Categories) != 8 || !summary.Block.IP.More {
		t.Fatal("unexpected routing summary, category bounds or counts")
	}
	projected, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{sourceURL, equivalentURL, aliasedHostURL, embeddedURL, hwid, datURL, "synthetic", "literal-direct.example", "198.51.100.0/24", subscriptionFirst} {
		if strings.Contains(string(projected), secret) {
			t.Fatal("preview disclosed private provider data")
		}
	}
	// The existing API status is independent of the page projection, and
	// Apply can still reuse the source checked by the new accessor.
	statusJSON, err := json.Marshal(details.Status)
	if err != nil || strings.Contains(string(statusJSON), "ru@news") {
		t.Fatal("routing detail appeared in the control API status")
	}
	cfg.Subscriptions[0] = source
	if err := d.ApplySubscriptionPreview(t.Context(), cfg, rev, subscription.PreviewRef{Source: source, ID: details.PreviewID}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("Apply did not reuse the checked subscription")
	}
}

func TestApplySubscriptionPreviewRechecksAfterGeodata(t *testing.T) {
	d, draft, provider := newRulesTestDaemon(t)
	initial := draft.Clone()
	initial.Subscriptions, initial.Groups, initial.ProviderRules = nil, nil, nil
	if err := d.Apply(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	rev := model.ConfigRevision(d.Config())
	original, err := os.ReadFile(d.opt.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	source := draft.Subscriptions[0]
	first := d.PreviewSubscriptionDetails(t.Context(), source)
	if first.Status.RulesState != ProviderRulesPending || provider.count("/geosite.dat") != 0 {
		t.Fatal("checked profile did not leave geodata evaluation pending")
	}

	release := make(chan struct{})
	provider.update(func(p *rulesProvider) { p.held["/geosite.dat"] = release })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- d.ApplySubscriptionPreview(ctx, draft, rev, subscription.PreviewRef{Source: source, ID: first.PreviewID})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for provider.count("/geosite.dat") == 0 {
		select {
		case err := <-done:
			t.Fatalf("Apply returned before evaluating geodata: %v", err)
		case <-ctx.Done():
			t.Fatal("Apply did not start geodata evaluation")
		case <-ticker.C:
		}
	}
	provider.update(func(p *rulesProvider) { p.routing = "happ://routing/off" })
	second := d.PreviewSubscriptionDetails(ctx, source)
	close(release)
	if second.Status.RulesState != ProviderRulesWithheld || second.PreviewID == first.PreviewID {
		t.Fatal("second check did not replace the retained preview")
	}
	select {
	case err := <-done:
		if !errors.Is(err, subscription.ErrPreviewChanged) {
			t.Fatalf("superseded in-flight Apply returned %v", err)
		}
	case <-ctx.Done():
		t.Fatal("superseded Apply did not return")
	}
	assertSavedBytes(t, d.opt.ConfigPath, original)
	if model.ConfigRevision(d.Config()) != rev || provider.count("/sub") != 2 {
		t.Fatal("superseded Apply changed the config or refetched the link")
	}
}

func TestApplySubscriptionPreviewKeepsRulesCompletedDuringLookup(t *testing.T) {
	const originalGeoip = "/geoip.dat"
	for _, tc := range []struct {
		name, checkedGeoip, wantError string
	}{
		{name: "same profile", checkedGeoip: originalGeoip},
		{name: "changed profile", checkedGeoip: "/updated/geoip.dat", wantError: "geoip file could not be downloaded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkPreviewKeepsRulesCompletedDuringLookup(t, originalGeoip, tc.checkedGeoip, tc.wantError)
		})
	}
}

func checkPreviewKeepsRulesCompletedDuringLookup(t *testing.T, originalGeoip, checkedGeoip, wantError string) {
	t.Helper()
	d, cfg, provider := newRulesTestDaemon(t)
	provider.update(func(p *rulesProvider) { delete(p.files, originalGeoip) })
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, _, state := d.ProviderRules(); state != ProviderRulesPartial {
		t.Fatalf("starting rules state is %s, want partial", state)
	}
	draft := d.Config()
	source := draft.Subscriptions[0]
	rev := model.ConfigRevision(draft)
	if checkedGeoip != originalGeoip {
		provider.useProfile("/geosite.dat", checkedGeoip, "domain:checked.example")
	}
	preview := d.PreviewSubscriptionDetails(t.Context(), source)
	if preview.PreviewID == 0 {
		t.Fatal("same-link preview did not produce a confirmation")
	}
	lookupCount := provider.count(checkedGeoip)
	release := make(chan struct{})
	provider.update(func(p *rulesProvider) { p.held[checkedGeoip] = release })
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- d.ApplySubscriptionPreview(ctx, draft, rev, subscription.PreviewRef{Source: source, ID: preview.PreviewID})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for provider.count(checkedGeoip) == lookupCount {
		select {
		case err := <-done:
			t.Fatalf("confirmation returned before its geodata request: %v", err)
		case <-ctx.Done():
			t.Fatal("confirmation did not request geodata")
		case <-ticker.C:
		}
	}

	// The first request is already waiting on release. Serve valid geodata
	// to the worker's retry while keeping the confirmation lookup held.
	provider.update(func(p *rulesProvider) {
		delete(p.held, checkedGeoip)
		p.files[originalGeoip] = testGeoipData
	})
	retry := claimSubscriptionRequest(d, rulesRetryFirst+time.Second)
	if retry == nil || !retry.rulesOnly {
		t.Fatal("background worker did not claim a geodata retry")
	}
	d.runSubscriptionRequest(ctx, retry)
	complete := requireAppliedProviderRules(t, d)
	if model.ConfigRevision(d.Config()) != rev {
		t.Fatal("background retry changed the checked configuration revision")
	}

	// The held lookup now fails. Its confirmation still uses the same
	// source, checked attempt, and config revision.
	provider.update(func(p *rulesProvider) { delete(p.files, checkedGeoip) })
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("confirmation did not apply: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("confirmation did not return")
	}
	got, _, state := d.ProviderRules()
	if state != ProviderRulesReady || !reflect.DeepEqual(got, complete) {
		t.Errorf("confirmation replaced completed live rules with %s rules", state)
	}
	if got := d.Subscriptions()[0].RulesError; got != wantError {
		t.Errorf("live rules diagnostic = %q, want %q", got, wantError)
	}
	raw, err := os.ReadFile(d.subscriptionSnapshotPath(d.Config()))
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]subscriptionSnapshot
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	snapshot := saved[subscriptionFingerprint(source)]
	if !snapshot.Rules.complete() || !reflect.DeepEqual(snapshot.Rules.Built, &complete) ||
		snapshot.Rules.Profile == nil || snapshot.Rules.Profile.GeoipURL != provider.URL+originalGeoip {
		t.Error("confirmation did not persist the complete rules")
	}
	if snapshot.Rules.Error != wantError {
		t.Errorf("saved rules diagnostic = %q, want %q", snapshot.Rules.Error, wantError)
	}
	wantLookups := lookupCount + 1
	if originalGeoip == checkedGeoip {
		wantLookups++
	}
	if provider.count("/sub") != 2 || provider.count(checkedGeoip) != wantLookups {
		t.Error("confirmation did not reuse the checked subscription or added a geodata request")
	}
}

func TestApplySubscriptionPreviewUsesCheckedCatalogForSameLink(t *testing.T) {
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if !d.CheckSubscription(cfg.Subscriptions[0].ID, "") || d.Subscriptions()[0].CheckProgress == nil {
		t.Fatal("could not queue a sweep of the currently applied nodes")
	}
	provider.response.Store(&subscriptionTestResponse{body: subscriptionSecond})
	candidate := d.PreviewSubscriptionDetails(t.Context(), cfg.Subscriptions[0])
	cfg = d.Config()
	checked := subscription.PreviewRef{Source: cfg.Subscriptions[0], ID: candidate.PreviewID}
	if err := d.ApplySubscriptionPreview(t.Context(), cfg, model.ConfigRevision(cfg), checked); err != nil {
		t.Fatal(err)
	}
	status := d.Subscriptions()[0]
	if len(status.Nodes) != 1 || status.Nodes[0].Name != "Second" || provider.requests.Load() != 2 {
		t.Fatal("confirming the same link did not install the checked catalog")
	}
	if status.CheckProgress != nil {
		t.Fatal("the confirmed catalog retained a check sweep of removed nodes")
	}
}

func TestApplyCheckedSubscriptionRejectsSupersededPreview(t *testing.T) {
	for _, tc := range []struct {
		name         string
		headers      http.Header
		acceptLatest bool
	}{
		{name: "different nodes", acceptLatest: true},
		{name: "expired", headers: http.Header{
			"Subscription-Userinfo": {fmt.Sprintf("expire=%d", time.Now().Add(-time.Hour).Unix())},
		}},
		{name: "device limit", headers: http.Header{"X-Hwid-Limit": {"true"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := new(subscriptionTestProvider)
			provider.response.Store(&subscriptionTestResponse{body: subscriptionFirst})
			d, draft := newSubscriptionTestDaemon(t, provider)
			initial := draft.Clone()
			initial.Subscriptions, initial.Groups = nil, nil
			if err := d.Apply(t.Context(), initial); err != nil {
				t.Fatal(err)
			}
			rev := model.ConfigRevision(d.Config())
			saved, err := os.ReadFile(d.opt.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			source := draft.Subscriptions[0]
			first := d.PreviewSubscriptionDetails(t.Context(), source)
			if first.Status.State != subscription.StateReady {
				t.Fatal("initial check was not ready")
			}
			provider.response.Store(&subscriptionTestResponse{body: subscriptionSecond, headers: tc.headers})
			second := d.PreviewSubscriptionDetails(t.Context(), source)
			if model.ConfigRevision(d.Config()) != rev {
				t.Fatal("check changed the applied config")
			}
			rejected := []uint64{first.PreviewID}
			if !tc.acceptLatest {
				rejected = append(rejected, second.PreviewID)
			}
			for _, id := range rejected {
				err := d.ApplySubscriptionPreview(t.Context(), draft, rev, subscription.PreviewRef{Source: source, ID: id})
				if !errors.Is(err, subscription.ErrPreviewChanged) {
					t.Errorf("obsolete or ineligible confirmation returned %v", err)
				}
			}
			if raw, err := os.ReadFile(d.opt.ConfigPath); err != nil || string(raw) != string(saved) {
				t.Error("obsolete confirmation changed the saved config")
			}
			if model.ConfigRevision(d.Config()) != rev || provider.requests.Load() != 2 {
				t.Error("obsolete confirmation changed the live config or refetched the subscription")
			}
			if tc.acceptLatest {
				err := d.ApplySubscriptionPreview(t.Context(), draft, rev, subscription.PreviewRef{Source: source, ID: second.PreviewID})
				if err != nil {
					t.Fatal(err)
				}
				if nodes := d.Subscriptions()[0].Nodes; len(nodes) != 1 || nodes[0].Name != "Second" || provider.requests.Load() != 2 {
					t.Fatal("fresh confirmation did not install the checked catalog")
				}
			}
		})
	}
}

func TestApplyIfCurrentRefusesConcurrentWriteDuringFetch(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	provider := diagnosticTransport(func(req *http.Request) (*http.Response, error) {
		close(started)
		select {
		case <-resume:
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(subscriptionFirst))}, nil
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	})
	d, draft := newSubscriptionTestDaemon(t, provider)
	initial := draft.Clone()
	initial.Subscriptions, initial.Groups = nil, nil
	if err := d.Apply(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rev := model.ConfigRevision(d.Config())
	done := make(chan error, 1)
	go func() { done <- d.ApplyIfCurrent(ctx, draft, rev) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("conditional Apply stopped before fetching: %v", err)
	case <-ctx.Done():
		t.Fatal("conditional Apply did not reach the provider")
	}

	other := d.Config()
	other.Paused = true
	if err := d.Apply(ctx, other); err != nil {
		t.Fatal(err)
	}
	close(resume)
	select {
	case err := <-done:
		if !errors.Is(err, model.ErrConfigChanged) {
			t.Fatalf("stale Apply returned %v", err)
		}
	case <-ctx.Done():
		t.Fatal("stale Apply did not finish")
	}
	if cfg := d.Config(); !cfg.Paused || len(cfg.Subscriptions) != 0 {
		t.Fatal("conditional Apply overwrote the configuration saved while it fetched")
	}
	raw, err := os.ReadFile(d.opt.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := model.Parse(raw)
	if err != nil || !saved.Paused || len(saved.Subscriptions) != 0 {
		t.Fatal("conditional Apply overwrote the persisted configuration")
	}
}
