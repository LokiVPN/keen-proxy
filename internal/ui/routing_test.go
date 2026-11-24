package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestRoutingModesRoundTrip(t *testing.T) {
	f := newOverviewFixture()
	f.cfg.ProviderRules.Disabled = []string{"block:geosite:ads"}
	h := New(f, setupTestOptions(RoleManage))
	assertRoutingMode(t, h, "provider")
	for _, tc := range []struct {
		mode, def string
		off       bool
	}{
		{"all", f.cfg.Networks[0].Target, true},
		{"own", model.TargetDirect, true},
		{"provider", model.DefaultProfile, false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			resp := setupRequest(h, "/routing", url.Values{"rev": {Revision(f.Config())}, "mode": {tc.mode}})
			if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/routing" {
				t.Fatalf("mode save returned HTTP %d, location %q", resp.Code, resp.Header().Get("Location"))
			}
			if got := f.cfg.Networks[0].Default; got != tc.def {
				t.Errorf("default = %q, want %q", got, tc.def)
			}
			rules := f.cfg.ProviderRules
			if rules == nil || rules.Off != tc.off || rules.Source != "sample" || !slices.Equal(rules.Disabled, []string{"block:geosite:ads"}) {
				t.Errorf("provider rules = %+v, want off=%v with saved source and switch", rules, tc.off)
			}
			get := httptest.NewRequest(http.MethodGet, "/routing", nil)
			for _, cookie := range resp.Result().Cookies() {
				get.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, get)
			assertContains(t, w.Body.String(), "Settings saved")
			assertRoutingMode(t, h, tc.mode)
		})
	}
}

func TestRoutingOwnListsAndOtherGroups(t *testing.T) {
	f := newOverviewFixture()
	f.cfg.Paused = true
	f.cfg.Networks[0].Mode = model.ModeOff
	f.cfg.Groups[2].Entries = []string{"custom.example"}
	want := f.Config()
	want.Groups[0].Entries = []string{"example.com", "198.51.100.0/24"}
	want.Groups[1].Entries = []string{"work.example"}
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/routing", nil)
	assertContains(t, page.Body.String(), "Additional routing groups are configured.", "local.example")
	resp := setupRequest(h, "/routing", url.Values{
		"rev": {formField(t, page.Body.String(), "rev")}, "mode": {"provider"},
		"own-vpn":    {"  *.EXAMPLE.COM. # a suffix\r\n\r\n# comment\r\n198.51.100.222/24"},
		"own-direct": {" .Work.example "},
	})
	if resp.Code != http.StatusSeeOther || f.applies != 1 || !reflect.DeepEqual(f.cfg, want) {
		t.Fatalf("own lists save HTTP %d, %d applies, groups %+v", resp.Code, f.applies, f.cfg.Groups)
	}
}

func TestRoutingModeEditsTheVisibleList(t *testing.T) {
	f := newRoutingFixture()
	f.cfg.Groups = []model.Group{
		{Name: "own-vpn", Target: f.cfg.Networks[0].Target, Entries: []string{"old-vpn.example"}},
		{Name: "own-direct", Target: model.TargetDirect, Entries: []string{"old-direct.example"}},
	}
	h := New(f, setupTestOptions(RoleManage))
	all := setupRequest(h, "/routing", url.Values{
		"rev": {Revision(f.Config())}, "mode": {"all"}, "own-vpn": {"ignored"}, "own-direct": {"new-direct.example"},
	})
	own := setupRequest(h, "/routing", url.Values{
		"rev": {Revision(f.Config())}, "mode": {"own"}, "own-vpn": {"new-vpn.example"}, "own-direct": {"ignored"},
	})
	if all.Code != http.StatusSeeOther || own.Code != http.StatusSeeOther {
		t.Fatalf("mode saves returned HTTP %d and %d", all.Code, own.Code)
	}
	if !slices.Equal(f.cfg.Groups[0].Entries, []string{"new-vpn.example"}) ||
		!slices.Equal(f.cfg.Groups[1].Entries, []string{"new-direct.example"}) {
		t.Errorf("switching modes overwrote a hidden list: %+v", f.cfg.Groups)
	}
}

func TestRoutingCreatesOwnGroupsAndSelectsTheMainSubscription(t *testing.T) {
	f := newRoutingFixture()
	f.cfg.ProviderRules = nil
	f.cfg.Subscriptions = append([]subscription.Source{{ID: "first", URL: "https://first.example/list"}}, f.cfg.Subscriptions...)
	f.cfg.Groups = nil
	f.cfg.Networks[0].Default = ""
	h := New(f, setupTestOptions(RoleManage))
	assertRoutingMode(t, h, "own")
	resp := setupRequest(h, "/routing", url.Values{
		"rev": {Revision(f.Config())}, "mode": {"provider"}, "own-vpn": {"vpn.example"}, "own-direct": {"direct.example"},
	})
	want := []model.Group{
		{Name: "own-vpn", Target: f.cfg.Networks[0].Target, Entries: []string{"vpn.example"}},
		{Name: "own-direct", Target: model.TargetDirect, Entries: []string{"direct.example"}},
	}
	if resp.Code != http.StatusSeeOther || !reflect.DeepEqual(f.cfg.Groups, want) {
		t.Fatalf("routing save returned HTTP %d with groups %+v", resp.Code, f.cfg.Groups)
	}
	if settings := f.cfg.ActiveProviderRules(); settings == nil || settings.Source != "sample" {
		t.Errorf("provider source selection = %+v, want the main subscription", settings)
	}
}

func TestRoutingWithoutSubscriptionOrHome(t *testing.T) {
	f := newRoutingFixture()
	f.cfg.Subscriptions, f.cfg.ProviderRules = nil, nil
	f.cfg.Networks[0].Target, f.cfg.Networks[0].Default = "old", "old"
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/routing", nil)
	assertContains(t, page.Body.String(), "Add a subscription to use provider rules.",
		`value="provider" id="routing-mode-provider" required disabled`)
	if resp := setupRequest(h, "/routing", url.Values{
		"rev": {Revision(f.Config())}, "mode": {"provider"},
	}); resp.Code != http.StatusUnprocessableEntity || f.applies != 0 {
		t.Fatalf("forged provider mode returned HTTP %d with %d applies", resp.Code, f.applies)
	}
	f.cfg.Networks = nil
	page = setupRequest(h, "/routing", nil)
	assertContains(t, page.Body.String(), "No home network configured.")
	if page.Code != http.StatusOK || strings.Contains(page.Body.String(), `action="/routing"`) {
		t.Errorf("page without a home network returned HTTP %d or showed an edit form", page.Code)
	}
}

func TestRoutingRejectsInvalidListEntries(t *testing.T) {
	f := newOverviewFixture()
	before := f.Config()
	h := New(f, setupTestOptions(RoleManage))
	resp := setupRequest(h, "/routing", url.Values{
		"rev": {Revision(before)}, "mode": {"provider"},
		"own-vpn":    {"valid.example\n<invalid>\n# comment\ngeoip:ru"},
		"own-direct": {"country:gb"},
	})
	if resp.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(before, f.Config()) {
		t.Fatalf("invalid submission returned HTTP %d and reached Apply %d times", resp.Code, f.applies)
	}
	body := resp.Body.String()
	assertContains(t, body, `aria-describedby="routing-vpn-errors"`, `aria-describedby="routing-direct-errors"`,
		"&lt;invalid&gt;", "Enter a domain, IP address, or subnet on line 2.", "Enter a domain, IP address, or subnet on line 4.",
		"Enter a domain, IP address, or subnet on line 1.")
}

func TestRoutingRevisionAndViewRole(t *testing.T) {
	f := newOverviewFixture()
	form := url.Values{"rev": {Revision(f.Config())}, "mode": {"own"}, "own-vpn": {"new.example"}}
	view := New(f, setupTestOptions(RoleView))
	page := setupRequest(view, "/routing", nil)
	assertContains(t, page.Body.String(), "View only", `<fieldset class="routing-fields" disabled>`)
	if resp := setupRequest(view, "/routing", form); resp.Code != http.StatusForbidden || f.applies != 0 {
		t.Fatalf("view POST returned HTTP %d with %d applies", resp.Code, f.applies)
	}

	f.cfg.Paused = true
	h := New(f, setupTestOptions(RoleManage))
	resp := setupRequest(h, "/routing", form)
	if resp.Code != http.StatusConflict || f.applies != 0 || !f.cfg.Paused {
		t.Fatalf("stale POST returned HTTP %d with %d applies", resp.Code, f.applies)
	}
	assertContains(t, resp.Body.String(), "Settings changed in another window",
		`name="rev" value="`+Revision(f.Config())+`"`)
}

func TestRoutingRevisionChangesDuringApplyValidation(t *testing.T) {
	f := routingConcurrentApply{newRoutingFixture()}
	h := New(f, setupTestOptions(RoleManage))
	resp := setupRequest(h, "/routing", url.Values{
		"rev": {Revision(f.Config())}, "mode": {"own"}, "own-vpn": {"outdated.example"},
	})
	if resp.Code != http.StatusConflict || !f.cfg.Paused || strings.Contains(resp.Body.String(), "outdated.example") {
		t.Fatalf("racing draft returned HTTP %d without a clean reload", resp.Code)
	}
	assertContains(t, resp.Body.String(), "Settings changed in another window",
		`name="rev" value="`+Revision(f.Config())+`"`)
}

type routingConcurrentApply struct{ *routingFixture }

func (f routingConcurrentApply) Apply(context.Context, *model.Config, string) error {
	// Daemon validation can return before the lock-protected revision check.
	f.cfg.Paused = true
	return errors.New("configuration rejected")
}

func TestRoutingProviderTable(t *testing.T) {
	f := newRoutingFixture()
	f.cfg.ProviderRules.Disabled = []string{"proxy:geosite:youtube"}
	h := New(f, setupTestOptions(RoleManage))
	en := setupRequest(h, "/routing", nil)
	assertPageHeaders(t, en.Result(), "en")
	body := en.Body.String()
	assertContains(t, body, "By Example VPN rules", "Example VPN rules", "Through VPN", "Direct", "Block",
		"YouTube", "Russian sites and services", "Other sites from the subscription (3)",
		"Other IP addresses from the subscription (2)", "Could not download category data.",
		"Rest of the traffic", "through VPN", "&lt;script&gt;", `value="proxy:geosite:youtube"`)
	for _, forbidden := range []string{"geoip:private", `type="checkbox" role="switch" name="enabled" value="direct:geoip:missing"`, "<script>alert", "synthetic-token", "style="} {
		if strings.Contains(body, forbidden) {
			t.Errorf("unexpected %q on the routing page", forbidden)
		}
	}
	if regexp.MustCompile(`value="proxy:geosite:youtube"[^>]* checked`).MatchString(body) {
		t.Error("a saved disabled rule rendered checked")
	}

	r := httptest.NewRequest(http.MethodGet, "/routing", nil)
	r.Header.Set("Accept-Language", "ru")
	ru := httptest.NewRecorder()
	h.ServeHTTP(ru, r)
	assertPageHeaders(t, ru.Result(), "ru")
	assertContains(t, ru.Body.String(), translations["ru"]["routing_category_category-ru"],
		"\u0414\u0440\u0443\u0433\u0438\u0435 \u0441\u0430\u0439\u0442\u044b \u0438\u0437 \u043f\u043e\u0434\u043f\u0438\u0441\u043a\u0438 (3)")
}

func TestRoutingRuleEditsAreLimitedToAvailableSubmittedRows(t *testing.T) {
	f := newRoutingFixture()
	f.cfg.ProviderRules.Disabled = []string{"proxy:geosite:youtube", "proxy:geosite:returned", "direct:geoip:missing", "direct:geosite:retired"}
	h := New(f, setupTestOptions(RoleManage))
	youtube, literals := "proxy:geosite:youtube", "proxy:literals:site"
	resp := setupRequest(h, "/routing", url.Values{
		"rev": {Revision(f.Config())}, "mode": {"provider"},
		"rule":    {youtube, literals, "direct:geoip:missing", "direct:geosite:retired", "direct:unrecognized"},
		"enabled": {youtube, "direct:geoip:missing", "direct:geosite:retired", "proxy:geosite:returned"},
	})
	want := []string{"proxy:geosite:returned", "direct:geoip:missing", "direct:geosite:retired", literals}
	if resp.Code != http.StatusSeeOther || !slices.Equal(f.cfg.ProviderRules.Disabled, want) {
		t.Errorf("rule save HTTP %d, keys %v, want %v", resp.Code, f.cfg.ProviderRules.Disabled, want)
	}
}

func TestRoutingProviderRuleStates(t *testing.T) {
	for _, tc := range []struct {
		state, message string
		hasProfile     bool
	}{
		{"pending", "Provider rules are pending evaluation.", false},
		{"withheld", "The provider does not supply routing rules.", false},
		{"failed", "Provider routing rules could not be loaded.", false},
		{"failed", "The provider sent no geosite file.", true},
		{"ready", "Rest of the traffic", true},
	} {
		t.Run(tc.message, func(t *testing.T) {
			f := newRoutingFixture()
			f.rules.State, f.rules.HasProfile, f.rules.GlobalProxy = tc.state, tc.hasProfile, false
			f.rules.Rules = nil
			if tc.state == "failed" && tc.hasProfile {
				f.rules.Rules = []RoutingRule{{Key: "proxy:geosite:youtube", Action: "proxy", Kind: "site", Source: "geosite:youtube", Unavailable: "provider sent no geosite file"}}
			}
			h := New(f, setupTestOptions(RoleManage))
			resp := setupRequest(h, "/routing", nil)
			body := resp.Body.String()
			if resp.Code != http.StatusOK {
				t.Fatalf("GET returned HTTP %d", resp.Code)
			}
			assertContains(t, body, tc.message)
			if tc.hasProfile {
				assertContains(t, body, "Rest of the traffic", ">directly</td>")
			} else if strings.Contains(body, "Rest of the traffic") {
				t.Error("unmatched traffic was labeled without a profile")
			}
			if strings.Contains(body, `role="switch"`) {
				t.Error("a missing or unavailable rule rendered a switch")
			}
		})
	}
}

type routingFixture struct {
	*overviewFixture
	rules RoutingRules
}

func (f *routingFixture) ProviderRules() RoutingRules { return f.rules }

func newRoutingFixture() *routingFixture {
	return &routingFixture{
		overviewFixture: newOverviewFixture(),
		rules: RoutingRules{
			Source: "sample", State: "partial", HasProfile: true, GlobalProxy: true,
			Rules: []RoutingRule{
				{Key: "direct:geosite:category-ru", Action: "direct", Kind: "site", Source: "geosite:category-ru"},
				{Key: "direct:geoip:missing", Action: "direct", Kind: "ip", Source: "geoip:missing", Unavailable: "geoip file could not be downloaded"},
				{Key: "direct:geoip:private", Action: "direct", Kind: "ip", Source: "geoip:private"},
				{Key: "proxy:geosite:youtube", Action: "proxy", Kind: "site", Source: "geosite:youtube"},
				{Key: "proxy:geosite:returned", Action: "proxy", Kind: "site", Source: "geosite:returned"},
				{Key: "proxy:literals:site", Action: "proxy", Kind: "site", Source: "literals", LiteralCount: 3},
				{Key: "proxy:literals:ip", Action: "proxy", Kind: "ip", Source: "literals", LiteralCount: 2},
				{Key: "block:geosite:<script>alert", Action: "block", Kind: "site", Source: "geosite:<script>alert"},
			},
		},
	}
}

func assertRoutingMode(t *testing.T, h http.Handler, mode string) {
	t.Helper()
	w := setupRequest(h, "/routing", nil)
	isSelected := regexp.MustCompile(`<input [^>]*name="mode" value="` + mode + `"[^>]* checked[ >]`).MatchString(w.Body.String())
	if w.Code != http.StatusOK || !isSelected {
		t.Errorf("GET /routing returned HTTP %d without %q selected", w.Code, mode)
	}
}
