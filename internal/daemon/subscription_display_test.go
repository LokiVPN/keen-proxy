package daemon

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

func TestSubscriptionNodeCredentialsStayOutOfCatalogViews(t *testing.T) {
	const compact = "a7e68fbacd3640799c4afa7b5c8d93a2"
	const canonical = "a7e68fba-cd36-4079-9c4a-fa7b5c8d93a2"
	const password = "fixture-password-keep-private"
	const combinedPassword = "hysteria-fixture:keep-private"
	const cookieValue = "xhttp-fixture-keep-private"
	labels := []string{strings.ToUpper(canonical), "%61" + compact[1:], strings.ToUpper(password), combinedPassword, cookieValue}
	const xhttpID = "119379fe-06d0-4982-bd4b-e5c530602a9c"
	xhttp := url.Values{"type": {"xhttp"}, "extra": {`{"headers":{"cOoKiE":["pref=basic; session=\"` + cookieValue + `\""]}}`}}
	provider := new(subscriptionTestProvider)
	provider.response.Store(&subscriptionTestResponse{body: strings.Join([]string{
		"vless://" + compact + "@first.example.test:443#" + url.PathEscape("Region "+labels[0]),
		"vless://" + canonical + "@second.example.test:443#" + url.PathEscape("Region "+labels[1]),
		"socks5://" + url.UserPassword("fixture-operator", base64.StdEncoding.EncodeToString([]byte(password))).String() +
			"@third.example.test:1080#" + url.PathEscape("Region "+labels[2]),
		"hysteria2://" + url.UserPassword("fixture-hy2", combinedPassword).String() +
			"@fourth.example.test:443#" + url.PathEscape("Region "+labels[3]),
		"vless://" + xhttpID + "@fifth.example.test:443?" + xhttp.Encode() + "#" + url.PathEscape("Region "+labels[4]),
		"socks5://sixth.example.test:1080#Safe%20region",
	}, "\n")})
	d, cfg := newSubscriptionTestDaemon(t, provider)
	source := cfg.Subscriptions[0]
	cfg.RouteHomeThroughSubscription(source.ID, netip.MustParsePrefix("192.0.2.0/24"))
	preview := d.PreviewSubscriptionDetails(t.Context(), source).Status
	wantNames := []string{"Node 1", "Node 2", "Node 3", "Node 4", "Node 5", "Safe region"}
	if len(preview.Nodes) != len(wantNames) {
		t.Fatalf("expected %d valid preview nodes, got %d", len(wantNames), len(preview.Nodes))
	}
	for i, want := range wantNames {
		if preview.Nodes[i].Name != want {
			t.Errorf("preview node %d does not have the expected safe name", i+1)
		}
	}
	if err := d.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	previewUI := ui.New(catalogPreviewDeps{overviewTestDeps{d: d}}, ui.Options{Role: func(*http.Request) ui.Role { return ui.RoleManage }})
	form := url.Values{"rev": {ui.Revision(d.Config())}, "url": {source.URL}}
	request := httptest.NewRequest(http.MethodPost, "/setup/check", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	checked := httptest.NewRecorder()
	previewUI.ServeHTTP(checked, request)
	body := checked.Body.String()
	if checked.Code != http.StatusOK || !strings.Contains(body, strings.Join(wantNames, ", ")) {
		t.Errorf("Setup preview returned HTTP %d or omitted the safe node names", checked.Code)
	}
	for _, private := range labels {
		if strings.Contains(body, private) {
			t.Error("Setup preview disclosed a node's dial credential")
		}
	}
	assertViews := func() {
		t.Helper()
		for _, role := range []ui.Role{ui.RoleManage, ui.RoleView} {
			h := ui.New(overviewTestDeps{d: d}, ui.Options{Role: func(*http.Request) ui.Role { return role }})
			for _, path := range []string{"/", "/connections", "/fragments/connections/" + source.ID} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				body := strings.ToLower(w.Body.String())
				if w.Code != http.StatusOK {
					t.Errorf("%s for role %v returned HTTP %d", path, role, w.Code)
				}
				for _, name := range wantNames {
					if !strings.Contains(body, strings.ToLower(name)) {
						t.Errorf("%s for role %v omitted %s", path, role, name)
					}
				}
				for _, private := range []string{compact, canonical, password, labels[1], combinedPassword, cookieValue} {
					if strings.Contains(body, private) {
						t.Errorf("%s for role %v disclosed a node's dial credential", path, role)
					}
				}
			}
		}
	}
	assertViews()
	// Recreate a snapshot from before the catalog-name protection existed.
	state := d.subscriptions.states[source.ID]
	for i := 2; i < len(labels); i++ {
		node := &state.snapshot.Nodes[i]
		node.Link, _, _ = strings.Cut(node.Link, "#")
		node.Name = "Legacy " + labels[i]
	}
	d.subscriptions.states[source.ID] = state
	if err := d.saveSubscriptionSnapshotsLocked(cfg); err != nil {
		t.Fatal(err)
	}
	d.loadSubscriptionSnapshotsLocked(t.Context(), cfg)
	assertViews()
}

type catalogPreviewDeps struct{ overviewTestDeps }

func (v catalogPreviewDeps) PreviewSubscription(ctx context.Context, source subscription.Source) ui.SetupPreview {
	details := v.d.PreviewSubscriptionDetails(ctx, source)
	status := details.Status
	result := ui.SetupPreview{State: status.State, Metadata: status.Metadata, NodeCount: len(status.Nodes), PreviewID: details.PreviewID}
	for _, node := range status.Nodes {
		result.NodeNames = append(result.NodeNames, node.Name)
	}
	return result
}
