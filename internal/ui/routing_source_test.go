package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestRoutingChangesSourceAndResetsRuleSwitches(t *testing.T) {
	f := newRoutingFixture()
	addSecondSubscription(f.overviewFixture)
	const key = "proxy:geosite:youtube"
	f.cfg.ProviderRules.Disabled = []string{"block:geosite:ads"}
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/routing", nil)
	form := url.Values{
		"rev": {formField(t, page.Body.String(), "rev")}, "mode": {"provider"}, "source": {"sub2"},
		"rule": {key}, "own-direct": {"new-direct.example"}, "remaining": {"vpn"},
	}
	form.Set("review_source", "1")
	review := setupRequest(h, "/routing", form)
	if review.Code != http.StatusOK || f.applies != 0 {
		t.Fatalf("source review returned HTTP %d with %d applies", review.Code, f.applies)
	}
	assertRemainingOption(t, review.Body.String(), "vpn", "Through VPN", true)
	assertRemainingOption(t, review.Body.String(), "profile", "As the subscription says</option>", false)
	form.Del("review_source")
	want := f.Config()
	want.ProviderRules.Source, want.ProviderRules.Disabled = "sub2", nil
	want.Networks[0].Default = want.Networks[0].Target
	want.Groups[1].Entries = []string{"new-direct.example"}
	post := setupRequest(h, "/routing", form)
	if post.Code != http.StatusSeeOther || post.Header().Get("Location") != "/routing" || f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
		t.Fatalf("source save returned HTTP %d, %d applies, rules %+v", post.Code, f.applies, f.cfg.ProviderRules)
	}
	assertContains(t, page.Body.String(), "Rules from subscription", `value="sample" selected`, "sub2 · Example VPN")
	get := httptest.NewRequest(http.MethodGet, "/routing", nil)
	for _, cookie := range post.Result().Cookies() {
		get.AddCookie(cookie)
	}
	result := httptest.NewRecorder()
	h.ServeHTTP(result, get)
	assertContains(t, result.Body.String(), `value="sub2" selected`, "Rule switches were reset", "Provider rules are pending evaluation.")
	if strings.Contains(result.Body.String(), key) {
		t.Error("the new source displayed a rule from the previous source")
	}
}

func TestRoutingReviewsWithholdingForTheSelectedSource(t *testing.T) {
	f := newRoutingFixture()
	addSecondSubscription(f.overviewFixture)
	f.subs[1].RulesWithheld = true
	before := f.Config()
	h := New(f, setupTestOptions(RoleManage))
	form := url.Values{"rev": {Revision(before)}, "source": {"sub2"}, "mode": {"provider"}, "own-direct": {"draft.example"}}
	post := setupRequest(h, "/routing", form)
	if post.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(f.Config(), before) {
		t.Fatalf("withheld source returned HTTP %d with %d applies", post.Code, f.applies)
	}
	assertContains(t, post.Body.String(), `value="sub2" selected`, `id="routing-mode-provider" required disabled`,
		"The provider does not supply routing rules.", "draft.example")

	// A dormant source can be saved even if it offers no rules.
	form.Set("mode", "own")
	post = setupRequest(h, "/routing", form)
	if post.Code != http.StatusSeeOther || f.cfg.ProviderRules.Source != "sub2" || !f.cfg.ProviderRules.Off {
		t.Fatalf("dormant source save returned HTTP %d, rules %+v", post.Code, f.cfg.ProviderRules)
	}
	page := setupRequest(h, "/routing", nil)
	assertContains(t, page.Body.String(), `id="routing-mode-provider" required disabled`)

	// Native forms can review a different candidate before enabling the mode.
	form.Set("rev", Revision(f.Config()))
	form.Set("source", "sample")
	form.Set("review_source", "1")
	form.Set("own-direct", "still-staged.example")
	post = setupRequest(h, "/routing", form)
	if post.Code != http.StatusOK || f.applies != 1 || f.cfg.ProviderRules.Source != "sub2" {
		t.Fatalf("source review returned HTTP %d and applied changes", post.Code)
	}
	assertContains(t, post.Body.String(), `value="sample" selected`, `id="routing-mode-provider" required>`, "still-staged.example")
}

func TestRoutingSavesListEditsAfterWithheldRulesReturn(t *testing.T) {
	f := newRoutingFixture()
	addSecondSubscription(f.overviewFixture)
	f.cfg.Networks[0].Default = f.cfg.Networks[0].Target
	f.cfg.ProviderRules.Disabled = []string{"block:geosite:ads"}
	f.rules = RoutingRules{Source: "sample", State: "withheld"}
	f.subs[0].RulesWithheld = true
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/routing", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("GET /routing returned HTTP %d", page.Code)
	}
	body := page.Body.String()
	assertContains(t, body, `value="sample" selected`, `id="routing-mode-provider" required checked disabled`,
		"The provider does not supply routing rules.")
	// The disabled radio contributes no mode field to this form.
	form := url.Values{
		"rev": {formField(t, body, "rev")}, "source": {"sample"},
		"own-vpn": {"vpn-edit.example"}, "own-direct": {"direct-edit.example"},
	}
	f.rules = RoutingRules{Source: "sample", State: "ready", HasProfile: true}
	f.subs[0].RulesWithheld = false
	want := f.Config()
	want.Groups[0].Entries = []string{"vpn-edit.example"}
	want.Groups[1].Entries = []string{"direct-edit.example"}
	post := setupRequest(h, "/routing", form)
	if post.Code != http.StatusSeeOther || f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
		t.Fatalf("list save after rules returned got HTTP %d and %d applies", post.Code, f.applies)
	}

	form.Set("rev", Revision(f.Config()))
	form.Set("source", "sub2")
	post = setupRequest(h, "/routing", form)
	if post.Code != http.StatusBadRequest || f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
		t.Fatalf("changing source without an explicit mode returned HTTP %d with %d applies", post.Code, f.applies)
	}
}

func TestRoutingSavesADifferentDormantSourceFromTheSelector(t *testing.T) {
	f := newRoutingFixture()
	addSecondSubscription(f.overviewFixture)
	f.cfg.ProviderRules = nil
	f.cfg.Networks[0].Default = model.TargetDirect
	want := f.Config()
	want.ProviderRules = &model.ProviderRulesSettings{Source: "sub2", Off: true}
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/routing", nil)
	assertContains(t, page.Body.String(), `value="sample" selected`)
	post := setupRequest(h, "/routing", url.Values{
		"rev": {formField(t, page.Body.String(), "rev")}, "mode": {"own"}, "source": {"sub2"},
	})
	if post.Code != http.StatusSeeOther || f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
		t.Fatalf("dormant selection returned HTTP %d, %d applies, rules %+v", post.Code, f.applies, f.cfg.ProviderRules)
	}
}

func TestRoutingRejectsIneligibleSourceSubmissions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    Role
		rev     string
		sources []string
		code    int
	}{
		{"unknown", RoleManage, "current", []string{"missing"}, http.StatusUnprocessableEntity},
		{"empty", RoleManage, "current", []string{""}, http.StatusUnprocessableEntity},
		{"multiple", RoleManage, "current", []string{"sample", "sub2"}, http.StatusUnprocessableEntity},
		{"stale", RoleManage, "stale", []string{"sub2"}, http.StatusConflict},
		{"view", RoleView, "current", []string{"sub2"}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRoutingFixture()
			addSecondSubscription(f.overviewFixture)
			before := f.Config()
			rev := tc.rev
			if rev == "current" {
				rev = Revision(before)
			}
			h := New(f, setupTestOptions(tc.role))
			post := setupRequest(h, "/routing", url.Values{"rev": {rev}, "mode": {"own"}, "source": tc.sources})
			if post.Code != tc.code || f.applies != 0 || !reflect.DeepEqual(f.Config(), before) {
				t.Fatalf("source submission returned HTTP %d, want %d, applies %d", post.Code, tc.code, f.applies)
			}
		})
	}
}

func addSecondSubscription(f *overviewFixture) {
	f.cfg.Subscriptions = append(f.cfg.Subscriptions, subscription.Source{ID: "sub2", URL: "https://second.example/list"})
	sub := f.subs[0]
	sub.ID = "sub2"
	f.subs = append(f.subs, sub)
}
