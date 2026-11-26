package ui

import (
	"cmp"
	"context"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	testSubscriptionNew     = "/connections/subscriptions/new"
	testSubscriptionReplace = "/connections/subscriptions/new/replace"
	testSubscriptionRemove  = "/connections/subscriptions/new/remove"
)

func TestSubscriptionLabelsUseUniqueDisplayTitles(t *testing.T) {
	for _, tc := range []struct {
		name, first, second, firstLabel, secondLabel string
	}{
		{name: "single", first: "Example VPN", firstLabel: "Example VPN"},
		{name: "unique", first: "Example VPN", second: "Other provider", firstLabel: "Example VPN", secondLabel: "Other provider"},
		{name: "untitled", first: "Example VPN", firstLabel: "Example VPN", secondLabel: "Subscription"},
		{name: "matching fallback", first: "Subscription", firstLabel: "sample · Subscription", secondLabel: "new · Subscription"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubscriptionManagementFixture(t)
			f.subs[0].Metadata.Title, f.subs[1].Metadata.Title = tc.first, tc.second
			if tc.secondLabel == "" {
				f.cfg.Subscriptions = f.cfg.Subscriptions[:1]
				f.subs[1].Metadata.Title = tc.first // A stale observation should not add a suffix.
			} else if tc.second == "" {
				f.subs = f.subs[:1] // A configured source without status still has a fallback label.
			}
			h := New(f, setupTestOptions(RoleManage))
			overview := setupRequest(h, "/", nil).Body.String()
			assertContains(t, overview, `<optgroup label="`+tc.firstLabel+`">`)
			if tc.secondLabel != "" {
				assertContains(t, overview, `<optgroup label="`+tc.secondLabel+`">`)
			}
			routing := setupRequest(h, "/routing", nil).Body.String()
			assertContains(t, routing, `<option value="sample" selected>`+tc.firstLabel+`</option>`)
			if tc.secondLabel != "" {
				assertContains(t, routing, `<option value="new">`+tc.secondLabel+`</option>`)
			}
			connections := setupRequest(h, "/connections", nil).Body.String()
			assertContains(t, connections, `>`+tc.first+`</h2>`)
			if tc.secondLabel != "" {
				assertContains(t, connections, `id="subscription-title-new" title="`+cmp.Or(tc.second, "Subscription")+`"`)
			}
			wantCaptions := 0
			if tc.name == "matching fallback" {
				wantCaptions = 2
			}
			for _, body := range []string{overview, connections} {
				if got := strings.Count(body, `>Subscription ID `); got != wantCaptions {
					t.Errorf("subscription ID captions = %d, want %d", got, wantCaptions)
				}
			}
		})
	}
}

func TestSubscriptionManagementDistinguishesMatchingTitles(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	title := "Identical provider title"
	f.subs[0].Metadata.Title, f.subs[1].Metadata.Title = title, title
	f.subs[1].Nodes = slices.Clone(f.subs[0].Nodes)
	f.cfg.ProviderRules = &model.ProviderRulesSettings{Source: "new"}
	h := New(f, setupTestOptions(RoleManage))

	page := setupRequest(h, "/connections", nil)
	body := page.Body.String()
	if page.Code != http.StatusOK || strings.Count(body, ">"+title+"</h2>") != 2 {
		t.Fatal("both matching subscription cards should render")
	}
	for _, id := range []string{"sample", "new"} {
		base := "/connections/subscriptions/" + id
		description := `aria-describedby="subscription-label-` + id + `"`
		assertContains(t, body, `>Subscription ID `+id+`</span>`,
			`id="subscription-label-`+id+`"`,
			`href="`+base+`/replace" `+description, description+` type="submit" form="subscription-remove-`+id+`"`)

		preview := setupRequest(h, base+"/replace", nil)
		if preview.Code != http.StatusOK {
			t.Fatalf("replacement for %s returned HTTP %d", id, preview.Code)
		}
		assertContains(t, preview.Body.String(), title, `>Subscription ID `+id+`</span>`)
		refused := setupRequest(h, base+"/remove", url.Values{"rev": {Revision(f.Config())}})
		if refused.Code != http.StatusConflict {
			t.Fatalf("referenced removal for %s returned HTTP %d", id, refused.Code)
		}
		assertContains(t, refused.Body.String(), "Remove these references before removing subscription "+id+".")
		for _, result := range []string{body, preview.Body.String(), refused.Body.String()} {
			if strings.Contains(result, "second-private") || strings.Contains(result, "synthetic-token") {
				t.Fatal("the stable labels exposed subscription links")
			}
		}
	}
	overview := setupRequest(h, "/", nil)
	assertContains(t, overview.Body.String(), `>Subscription ID sample</span>`,
		`<optgroup label="sample · `+title+`">`, `<optgroup label="new · `+title+`">`)
	for _, id := range []string{"sample", "new"} {
		assertContains(t, overview.Body.String(),
			`value="subscription:`+id+`:auto"`, `>`+id+` · Auto — switch nodes on failure</option>`,
			`>`+id+` · North · 42 ms</option>`)
	}
	routing := setupRequest(h, "/routing", nil)
	assertContains(t, routing.Body.String(), "By new · "+title+" rules",
		`<option value="sample">sample · `+title+`</option>`, `<option value="new" selected>new · `+title+`</option>`)

	fragment := setupRequest(h, "/fragments/connections/sample", nil)
	assertContains(t, fragment.Body.String(), `>Subscription ID sample</span>`, `id="subscription-label-sample"`)
	f.subs[1].Metadata.Title = "Renamed provider"
	fragment = setupRequest(h, "/fragments/connections/sample", nil)
	assertContains(t, fragment.Body.String(), `id="subscription-label-sample"`, `>`+title+`</h2>`)
	if fragment.Code != http.StatusOK || strings.Contains(fragment.Body.String(), ">Subscription ID ") {
		t.Fatal("the fragment kept an ID after the display title became unique")
	}
}

func TestSubscriptionLabelsDistinguishLiteralAndGeneratedTitles(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	f.subs[0].Metadata.Title, f.subs[1].Metadata.Title = "Example VPN", "Example VPN"
	for _, source := range []struct{ id, title string }{
		{"literal-suffix", "Example VPN · new"},
		{"literal-prefix", "new · Example VPN"},
	} {
		f.cfg.Subscriptions = append(f.cfg.Subscriptions, subscription.Source{ID: source.id, URL: "https://example.test/" + source.id})
		f.subs = append(f.subs, AppliedSubscription{ID: source.id, Metadata: subscription.Metadata{Title: source.title}})
	}
	h := New(f, setupTestOptions(RoleManage))
	overview := setupRequest(h, "/", nil).Body.String()
	routing := setupRequest(h, "/routing", nil).Body.String()
	assertContains(t, routing, `<option value="literal-suffix">Example VPN · new</option>`,
		`<option value="literal-prefix">new · Example VPN</option>`)
	for _, title := range []string{"Example VPN · new", "new · Example VPN"} {
		if strings.Count(overview, `<optgroup label="`+title+`">`) != 1 || strings.Count(routing, `>`+title+`</option>`) != 1 {
			t.Errorf("provider title %q does not identify exactly one subscription in both selectors", title)
		}
	}
}

func TestSubscriptionManagementRejectsCheckWithoutReturningLink(t *testing.T) {
	const token = "synthetic-rejected-credential"
	valid := "https://provider.example/secret?key=" + token
	for _, tc := range []struct {
		name, link, state, message string
		status                     int
		expire                     int64
	}{
		{"malformed", "https://provider.example/%xx?key=" + token, "", "Enter a valid HTTPS subscription link.", http.StatusBadRequest, 0},
		{"invalid scheme", "http://provider.example/" + token, "", "Enter a valid HTTPS subscription link.", http.StatusBadRequest, 0},
		{"network error", valid, subscription.StateNetworkError, "Could not check the subscription.", http.StatusOK, 0},
		{"HTTP error", valid, subscription.StateHTTPError, "Could not check the subscription.", http.StatusOK, 0},
		{"unusable list", valid, subscription.StateUnsupported, "Could not check the subscription.", http.StatusOK, 0},
		{"expired", valid, subscription.StateReady, "The subscription expired on", http.StatusOK, time.Now().Add(-time.Hour).Unix()},
		{"device limit", valid, subscription.StateHWIDLimit, "All device slots", http.StatusOK, 0},
	} {
		for _, base := range []string{testSubscriptionNew, testSubscriptionReplace, "/setup"} {
			t.Run(base+"/"+tc.name, func(t *testing.T) {
				f := newSubscriptionManagementFixture(t)
				f.preview.State = tc.state
				f.preview.Metadata.Usage = &subscription.Usage{Expire: tc.expire}
				h := New(f, setupTestOptions(RoleManage))
				w := setupRequest(h, base+"/check", url.Values{"rev": {Revision(f.Config())}, "url": {tc.link}})
				assertPageHeaders(t, w.Result(), "en")
				body := w.Body.String()
				if w.Code != tc.status || !strings.Contains(body, tc.message) || !strings.Contains(body, `action="`+base+`/check"`) {
					t.Fatalf("rejected check returned HTTP %d or lost its error or retry", w.Code)
				}
				if strings.Contains(body, token) || strings.Contains(body, `name="preview"`) {
					t.Fatal("rejected check must offer an empty retry field and omit the private link and confirmation")
				}
				input := connectionControl(t, body, "input", "url", "")
				if _, disabled := input["disabled"]; disabled {
					t.Fatal("rejected check disabled the retry field")
				}
				if f.applies != 0 || (tc.status == http.StatusBadRequest && f.checks != 0) {
					t.Fatal("rejected check reached an unexpected operation")
				}
			})
		}
	}
}

func TestSubscriptionManagementAddsCheckedSource(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	f.cfg.Subscriptions[1].ID = "sub3"
	f.cfg.Connections = append(f.cfg.Connections,
		model.Connection{ID: "sub2", Type: model.ConnLink, Link: "socks5://example.test:1080", Disabled: true},
		model.Connection{ID: "subscription:sub5:auto", Type: model.ConnLink, Link: "socks5://example.test:1080"},
	)
	f.runtimeTags = []string{"sub4", "subscription:sub6:" + overviewNodeID}
	f.rawIDs = map[string][]string{"sub7": {"legacy-selector"}}
	want := f.Config()
	want.Subscriptions = append(want.Subscriptions, subscription.Source{ID: "sub8", URL: setupTestURL, SendHWID: true})
	h := New(f, setupTestOptions(RoleManage))

	form := checkSubscriptionLink(t, h, testSubscriptionNew, "Add subscription")
	expectSubscriptionApply(t, f, 0, "sub8")
	if got := setupRequest(h, "/setup/enable", form); got.Code != http.StatusConflict {
		t.Fatalf("add draft on legacy setup returned HTTP %d, want 409", got.Code)
	}
	if got := setupRequest(h, "/connections/subscriptions/sample/replace/confirm", form); got.Code != http.StatusConflict {
		t.Fatalf("add draft on replacement returned HTTP %d, want 409", got.Code)
	}

	fresh := checkSubscriptionLink(t, h, testSubscriptionNew, "Add subscription")
	if got := setupRequest(h, testSubscriptionNew+"/confirm", form); got.Code != http.StatusConflict {
		t.Fatalf("superseded add draft returned HTTP %d, want 409", got.Code)
	}
	expectSubscriptionApply(t, f, 0, "sub8")
	fresh.Set("id", "sample")
	fresh.Set("url", "https://provider.example/unchecked-link")
	if got := setupRequest(h, testSubscriptionNew+"/confirm", fresh); got.Code != http.StatusSeeOther ||
		got.Header().Get("Location") != "/connections" || len(got.Result().Cookies()) == 0 {
		t.Fatalf("add confirmation returned HTTP %d, location %q or missing flash", got.Code, got.Header().Get("Location"))
	}
	if !reflect.DeepEqual(f.Config(), want.Clone()) {
		t.Fatal("add did not append only the checked source")
	}
	if got := setupRequest(h, testSubscriptionNew+"/confirm", fresh); got.Code != http.StatusConflict {
		t.Fatalf("replayed add draft returned HTTP %d, want 409", got.Code)
	}
	expectSubscriptionApply(t, f, 1, "sub8")
}

func TestSubscriptionManagementReplacesOnlySelectedSource(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	f.cfg.ProviderRules = &model.ProviderRulesSettings{Source: "new", Disabled: []string{"proxy:geosite:video"}}
	f.cfg.Groups[0].Target = model.ManagedTarget("new", "auto")
	f.preview.Routing = &subscription.RoutingSummary{Name: "Provider rules"}
	want := f.Config()
	want.Subscriptions[1].URL, want.Subscriptions[1].SendHWID = setupTestURL, true
	h := New(f, setupTestOptions(RoleManage))

	form := checkSubscriptionLink(t, h, testSubscriptionReplace, "Replace link",
		"Alt &lt;subscription&gt;", "KeenProxy evaluates these rules when you replace the link.")
	for _, wrong := range []string{testSubscriptionNew + "/confirm", "/connections/subscriptions/sample/replace/confirm"} {
		if got := setupRequest(h, wrong, form); got.Code != http.StatusConflict {
			t.Errorf("replacement draft at %s returned HTTP %d, want 409", wrong, got.Code)
		}
	}
	expectSubscriptionApply(t, f, 0, "new")
	if got := setupRequest(h, testSubscriptionReplace+"/confirm", form); got.Code != http.StatusSeeOther || got.Header().Get("Location") != "/connections" {
		t.Fatalf("replace confirmation returned HTTP %d or the wrong location", got.Code)
	}
	expectSubscriptionApply(t, f, 1, "new")
	if !reflect.DeepEqual(f.Config(), want.Clone()) {
		t.Fatal("replace changed fields outside the selected source's URL and HWID setting")
	}
}

func TestSubscriptionManagementRefusesStaleAndMissingSources(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	h := New(f, setupTestOptions(RoleManage))
	form := checkSubscriptionLink(t, h, testSubscriptionReplace, "Replace link")
	f.cfg.Paused = !f.cfg.Paused
	for _, path := range []string{testSubscriptionReplace + "/confirm", testSubscriptionRemove, testSubscriptionNew + "/check"} {
		w := setupRequest(h, path, form)
		if w.Code != http.StatusConflict {
			t.Errorf("stale POST %s returned HTTP %d, want 409", path, w.Code)
		}
		assertContains(t, w.Body.String(), "Settings changed in another window")
	}
	f.cfg.Subscriptions = f.cfg.Subscriptions[:1]
	for _, suffix := range []string{"/check", "/confirm"} {
		path := testSubscriptionReplace + suffix
		w := setupRequest(h, path, url.Values{"rev": {Revision(f.Config())}, "url": {setupTestURL}, "preview": form["preview"]})
		if w.Code != http.StatusNotFound {
			t.Errorf("POST %s for a missing source returned HTTP %d, want 404", path, w.Code)
		}
	}
	for _, path := range []string{testSubscriptionReplace, testSubscriptionRemove} {
		w := setupRequest(h, path, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s returned HTTP %d, want 404", path, w.Code)
		}
	}
	if f.checks != 1 || f.applies != 0 {
		t.Fatalf("stale or missing source reached preview or Apply (%d checks, %d applies)", f.checks, f.applies)
	}
}

func TestSubscriptionManagementListsEveryRemovalReference(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	auto := model.ManagedTarget("new", "auto")
	f.cfg.Networks[0].Target = auto
	f.cfg.Networks = append(f.cfg.Networks, model.Network{
		Name: "Guest <LAN>", CIDR: "203.0.113.0/24", Mode: model.ModeSplit,
		Default: model.ManagedTarget("new", model.SubscriptionStickySession),
	})
	f.cfg.Groups[0].Target = model.ManagedTarget("new", overviewNodeID)
	// Reserves can only select manual connections today. Exercise the guard
	// with legacy/malformed references so it identifies each before Apply.
	f.cfg.Connections[0].Fallback = auto
	f.cfg.Subscriptions[0].Fallback = auto
	f.cfg.Clients = append(f.cfg.Clients, model.Client{Name: "Desktop", MAC: "02:00:00:00:00:05", Target: auto})
	f.cfg.ProviderRules = &model.ProviderRulesSettings{Source: "new"}
	f.rawIDs = map[string][]string{"new": {f.cfg.Connections[1].ID}}
	before := Revision(f.Config())
	h := New(f, setupTestOptions(RoleManage))
	w := setupRequest(h, testSubscriptionRemove, url.Values{"rev": {before}})
	if w.Code != http.StatusConflict {
		t.Fatalf("referenced removal returned HTTP %d, want 409", w.Code)
	}
	assertPageHeaders(t, w.Result(), "en")
	body := w.Body.String()
	assertContains(t, body, "Remove these references before removing subscription new.", "<ul>",
		"Main connection for Home", "Default route for Guest &lt;LAN&gt;", "Routing group own-vpn",
		"Reserve for Office", "Reserve for subscription sample", "Device Desktop", "Provider routing rules",
		"Sing-box profile Cabin")
	if strings.Contains(body, "second-private") || strings.Contains(body, "synthetic-token") {
		t.Fatal("the deletion guard disclosed a secret")
	}
	if f.applies != 0 || Revision(f.Config()) != before {
		t.Fatal("referenced removal reached Apply or changed the configuration")
	}
}

func TestSubscriptionManagementRemovesOnlyUnreferencedSource(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	// Older YAML can give a manual connection the same plain ID as a
	// subscription. Plain route targets still refer to that connection.
	f.cfg.Connections = append(f.cfg.Connections, model.Connection{
		ID: "new", Type: model.ConnLink, Link: "socks5://example.test:1080",
	})
	f.cfg.Networks[0].Default = "new"
	want := f.Config()
	want.Subscriptions = want.Subscriptions[:1]
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/connections", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("GET /connections returned HTTP %d", page.Code)
	}
	assertContains(t, page.Body.String(), `href="`+testSubscriptionNew+`"`, `href="`+testSubscriptionReplace+`"`,
		`method="post" action="`+testSubscriptionRemove+`"`, `name="rev" value="`+Revision(f.Config())+`"`,
		`href="/connections/subscriptions/sample/replace"`, `name="fallback.new"`, `value="new"`, "Alt &lt;subscription&gt;", "West", "North")
	form := url.Values{"rev": {formField(t, page.Body.String(), "rev")}, "fallback.sample": {"block"}}
	w := setupRequest(h, testSubscriptionRemove, form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/connections" || f.applies != 1 {
		t.Fatalf("remove returned HTTP %d with %d applies", w.Code, f.applies)
	}
	if !reflect.DeepEqual(f.Config(), want.Clone()) {
		t.Fatal("removal changed other subscriptions or configuration fields")
	}
	r := setupRequest(h, "/connections", nil)
	if strings.Contains(r.Body.String(), testSubscriptionReplace) || strings.Contains(r.Body.String(), "Alt &lt;subscription&gt;") {
		t.Fatal("a removed source still renders a subscription block")
	}
}

func TestSubscriptionManagementRemovesTrialAfterAnUnrelatedListSave(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	f.cfg.Subscriptions, f.subs, f.cfg.ProviderRules = nil, nil, nil
	f.cfg.Networks[0].Target, f.cfg.Networks[0].Default = "old", model.TargetDirect
	f.cfg.Groups[0].Target = "old"
	want := f.Config()
	want.Groups[1].Entries = []string{"exception.example"}
	h := New(f, setupTestOptions(RoleManage))
	start := setupRequest(h, "/connections", nil)
	assertContains(t, start.Body.String(), `href="/setup"`)
	if w := setupRequest(h, "/setup/enable", checkSetupLink(t, h)); w.Code != http.StatusSeeOther {
		t.Fatalf("adding the trial returned HTTP %d", w.Code)
	}
	const trial = setupSourceID
	if len(f.cfg.Subscriptions) != 1 || f.cfg.Subscriptions[0].ID != trial {
		t.Fatal("the check and confirm flow did not add the trial subscription")
	}
	page := setupRequest(h, "/routing", nil)
	assertContains(t, page.Body.String(), `value="`+trial+`" selected`, `name="mode" value="own" id="routing-mode-own" required checked`)
	post := setupRequest(h, "/routing", url.Values{
		"rev": {formField(t, page.Body.String(), "rev")}, "mode": {"own"}, "source": {trial},
		"own-direct": {"exception.example"},
	})
	if post.Code != http.StatusSeeOther || f.cfg.ProviderRules != nil {
		t.Fatalf("site-list save returned HTTP %d and rules %+v", post.Code, f.cfg.ProviderRules)
	}
	connections := setupRequest(h, "/connections", nil)
	remove := subscriptionPath(trial) + "/remove"
	assertContains(t, connections.Body.String(), `action="`+remove+`"`)
	post = setupRequest(h, remove, url.Values{"rev": {formField(t, connections.Body.String(), "rev")}})
	if post.Code != http.StatusSeeOther || f.applies != 3 || !reflect.DeepEqual(f.Config(), want) {
		t.Fatalf("trial removal returned HTTP %d with %d applies or changed other settings", post.Code, f.applies)
	}
}

func TestSubscriptionManagementClearsOnlyRemovedInactiveRules(t *testing.T) {
	for _, source := range []string{"new", "sample"} {
		t.Run(source, func(t *testing.T) {
			f := newSubscriptionManagementFixture(t)
			f.cfg.Networks[0].Default = model.TargetDirect
			f.cfg.ProviderRules = &model.ProviderRulesSettings{Source: source, Off: true, Disabled: []string{"block:geosite:ads"}}
			before := f.Config()
			want := before.Clone()
			want.Subscriptions = want.Subscriptions[:1]
			if source == "new" {
				want.ProviderRules = nil
			}
			h := New(f, setupTestOptions(RoleManage))
			post := setupRequest(h, testSubscriptionRemove, url.Values{"rev": {Revision(before)}})
			if post.Code != http.StatusSeeOther || post.Header().Get("Location") != "/connections" ||
				f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
				t.Fatalf("removal with rules off returned HTTP %d, %d applies, rules %+v", post.Code, f.applies, f.cfg.ProviderRules)
			}
		})
	}
}

func TestSubscriptionManagementViewRoleDisablesActions(t *testing.T) {
	f := newSubscriptionManagementFixture(t)
	h := New(f, setupTestOptions(RoleView))
	page := setupRequest(h, "/connections", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("viewer GET /connections returned HTTP %d", page.Code)
	}
	body := page.Body.String()
	assertContains(t, body, "View only", `type="button" disabled>Add subscription</button>`,
		`type="button" disabled>Replace link</button>`, `form="subscription-remove-new" disabled`)
	for _, path := range []string{testSubscriptionNew, testSubscriptionReplace} {
		if strings.Contains(body, `href="`+path+`"`) {
			t.Errorf("viewer received an enabled link to %s", path)
		}
		form := setupRequest(h, path, nil)
		if form.Code != http.StatusOK {
			t.Errorf("viewer GET %s returned HTTP %d", path, form.Code)
		}
		assertContains(t, form.Body.String(), "required disabled", `type="submit" disabled`)
	}
	post := url.Values{"rev": {Revision(f.Config())}, "url": {setupTestURL}}
	for _, endpoint := range []string{testSubscriptionNew + "/check", testSubscriptionNew + "/confirm",
		testSubscriptionReplace + "/check", testSubscriptionReplace + "/confirm", testSubscriptionRemove} {
		if w := setupRequest(h, endpoint, post); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "synthetic-token") {
			t.Errorf("forged view POST %s returned HTTP %d or disclosed link", endpoint, w.Code)
		}
	}
	if f.checks != 0 || f.applies != 0 {
		t.Fatal("viewer reached preview or Apply")
	}
}

type subscriptionManagementFixture struct {
	*connectionsFixture
	runtimeTags []string
	rawIDs      map[string][]string
}

func newSubscriptionManagementFixture(t *testing.T) *subscriptionManagementFixture {
	t.Helper()
	f := &subscriptionManagementFixture{connectionsFixture: newConnectionsFixture(t)}
	f.cfg.Subscriptions = append(f.cfg.Subscriptions, subscription.Source{
		ID: "new", URL: "https://other.example/second-private", Fallback: "backup",
	})
	f.subs = append(f.subs, AppliedSubscription{
		ID: "new", State: subscription.StateReady, Metadata: subscription.Metadata{Title: "Alt <subscription>"},
		Nodes: []SubscriptionNode{{ID: overviewNodeID, Name: "West"}},
	})
	f.preview = SetupPreview{State: subscription.StateReady, NodeCount: 1}
	return f
}

func (f *subscriptionManagementFixture) ConnectionRuntimeTags(*model.Config) ([]string, error) {
	return f.runtimeTags, nil
}

func (f *subscriptionManagementFixture) SubscriptionProfileReferences(_ context.Context, _ *model.Config, id string) ([]string, error) {
	return f.rawIDs[id], nil
}

func checkSubscriptionLink(t *testing.T, h http.Handler, path string, labels ...string) url.Values {
	t.Helper()
	page := setupRequest(h, path, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("GET %s returned HTTP %d, want 200", path, page.Code)
	}
	assertContains(t, page.Body.String(), `action="`+path+`/check"`)
	if strings.Contains(page.Body.String(), "private") || strings.Contains(page.Body.String(), "synthetic-token") {
		t.Fatal("the entry form exposed a saved link")
	}
	rev := formField(t, page.Body.String(), "rev")
	w := setupRequest(h, path+"/check", url.Values{"rev": {rev}, "url": {setupTestURL}})
	if w.Code != http.StatusOK {
		t.Fatalf("POST %s/check returned HTTP %d, want 200", path, w.Code)
	}
	assertPageHeaders(t, w.Result(), "en")
	body := w.Body.String()
	assertContains(t, body, append(labels, `action="`+path+`/confirm"`, `href="/connections"`)...)
	if strings.Contains(body, "synthetic-token") || strings.Contains(body, "second-private") {
		t.Fatal("successful check exposed one of the subscription links")
	}
	return url.Values{"rev": {rev}, "preview": {formField(t, body, "preview")}}
}

func expectSubscriptionApply(t *testing.T, f *subscriptionManagementFixture, count int, id string) {
	t.Helper()
	if f.applies != count || f.lanLookups != 0 || f.source != (subscription.Source{ID: id, URL: setupTestURL, SendHWID: true}) {
		t.Fatalf("expected checked source ID %q with HWID on, %d Apply calls and no LAN lookup, got ID %q, HWID %t, %d Apply calls and %d LAN lookups",
			id, count, f.source.ID, f.source.SendHWID, f.applies, f.lanLookups)
	}
}
