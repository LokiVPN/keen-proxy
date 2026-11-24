package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestSubscriptionPreviewDetailsProjectsPrivateRouting(t *testing.T) {
	const sourceURL = "https://provider.example/list?token=synthetic-preview-secret"
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
			"Name":        "<profile> " + sourceURL,
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
		headers.Set("announce", sourceURL+" "+hwid)
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader(subscriptionFirst))}, nil
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
		summary == nil || details.RoutingMalformed || hwid == "" {
		t.Fatal("expected a ready preview, a parsed summary and a device identity")
	}
	if calls != 1 || len(d.Subscriptions()) != 0 || model.ConfigRevision(d.Config()) != rev {
		t.Fatal("preview fetched geodata or changed the applied catalog")
	}
	if summary.GlobalProxy || summary.Name != "<profile> [redacted]" ||
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
	for _, secret := range []string{sourceURL, hwid, datURL, "literal-direct.example", "198.51.100.0/24", subscriptionFirst} {
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
	if err := d.ApplyIfCurrent(t.Context(), cfg, rev); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("Apply did not reuse the checked subscription")
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
