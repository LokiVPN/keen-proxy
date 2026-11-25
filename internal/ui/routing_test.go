package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
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

func TestRoutingBothListsCanBeSavedInEachMode(t *testing.T) {
	for _, mode := range []string{"all", "own", "provider"} {
		t.Run(mode, func(t *testing.T) {
			f := newRoutingFixture()
			h := New(f, setupTestOptions(RoleManage))
			w := setupRequest(h, "/routing", url.Values{
				"rev": {Revision(f.Config())}, "mode": {mode},
				"own-vpn": {"new-vpn.example"}, "own-direct": {"new-direct.example"},
			})
			if w.Code != http.StatusSeeOther ||
				!slices.Equal(f.cfg.Groups[0].Entries, []string{"new-vpn.example"}) ||
				!slices.Equal(f.cfg.Groups[1].Entries, []string{"new-direct.example"}) {
				t.Fatalf("save returned HTTP %d with groups %+v", w.Code, f.cfg.Groups)
			}
		})
	}
}

func TestRoutingRejectsTheSameEntryInBothLists(t *testing.T) {
	for _, tc := range []struct{ mode, field, value string }{
		{"all", "own-direct", "EXAMPLE.com. # same suffix"},
		{"own", "own-vpn", "198.51.100.44/24"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newRoutingFixture()
			f.cfg.Groups[0].Entries = []string{"*.example.com"}
			f.cfg.Groups[1].Entries = []string{"198.51.100.0/24"}
			before := f.Config()
			h := New(f, setupTestOptions(RoleManage))
			w := setupRequest(h, "/routing", url.Values{
				"rev": {Revision(before)}, "mode": {tc.mode}, tc.field: {tc.value},
			})
			if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(f.Config(), before) {
				t.Fatalf("conflicting save returned HTTP %d with %d applies", w.Code, f.applies)
			}
			assertContains(t, w.Body.String(), `aria-describedby="routing-vpn-errors"`, `aria-describedby="routing-direct-errors"`,
				"Remove entries that appear in both lists.", tc.value)
		})
	}
}

func TestRoutingModeSaveIgnoresOverlapsInReadOnlyLists(t *testing.T) {
	for _, name := range []string{"disabled lists", "advanced list", "main routes directly"} {
		t.Run(name, func(t *testing.T) {
			f := newRoutingFixture()
			f.cfg.Groups[0].Entries = []string{"shared.example"}
			f.cfg.Groups[1].Entries = []string{"*.SHARED.example."}
			switch name {
			case "disabled lists":
				f.cfg.Groups[0].Disabled, f.cfg.Groups[1].Disabled = true, true
			case "advanced list":
				f.cfg.Groups[0].Target = "old"
			case "main routes directly":
				f.status.Connections[f.cfg.Networks[0].Target] = ConnectionStatus{Class: stats.TargetDirect}
			}
			want := f.Config()
			want.ProviderRules.Off = true
			want.Networks[0].Default = model.TargetDirect
			h := New(f, setupTestOptions(RoleManage))
			w := setupRequest(h, "/routing", url.Values{"rev": {Revision(f.Config())}, "mode": {"own"}})
			if w.Code != http.StatusSeeOther || f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
				t.Fatalf("mode-only save returned HTTP %d with %d applies", w.Code, f.applies)
			}
		})
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

func TestRoutingRuleSwitchSurvivesRefresh(t *testing.T) {
	for _, state := range []string{"removed", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			f := newRoutingFixture()
			const youtube, returning, unchanged = "proxy:geosite:youtube", "proxy:geosite:returned", "direct:geosite:retired"
			f.cfg.ProviderRules.Disabled = []string{returning, unchanged}
			h := New(f, setupTestOptions(RoleManage))
			before := setupRequest(h, "/routing", nil).Body.String()
			assertContains(t, before, `name="rule" value="`+youtube+`"`, `name="rule" value="`+returning+`"`)
			original := f.rules
			f.rules.Rules = slices.Clone(original.Rules)
			if state == "removed" {
				f.rules.Rules = slices.DeleteFunc(f.rules.Rules, func(rule RoutingRule) bool { return rule.Key == youtube || rule.Key == returning })
			} else {
				for i := range f.rules.Rules {
					f.rules.Rules[i].Unavailable = "provider data not loaded"
				}
				f.rules.State = "failed"
			}

			w := setupRequest(h, "/routing", url.Values{
				"rev": {formField(t, before, "rev")}, "mode": {"provider"},
				"rule": {youtube, returning}, "enabled": {returning},
			})
			if w.Code != http.StatusSeeOther || !slices.Equal(f.cfg.ProviderRules.Disabled, []string{unchanged, youtube}) {
				t.Fatalf("rule save HTTP %d, disabled keys %v", w.Code, f.cfg.ProviderRules.Disabled)
			}
			f.rules = original
			after := setupRequest(h, "/routing", nil).Body.String()
			assertContains(t, after, `value="`+returning+`" checked`)
			if strings.Contains(after, `value="`+youtube+`" checked`) {
				t.Error("the returned rule came back enabled after being switched off")
			}
		})
	}
}

func TestRoutingProtectedSwitchCanReenableALegacyDisabledKey(t *testing.T) {
	f := newRoutingFixture()
	legacy := "proxy:geosite:https://provider.example/private?key=synthetic"
	key := model.RedactedProviderRuleKey(legacy)
	f.cfg.ProviderRules.Disabled = []string{legacy}
	f.rules.Rules = []RoutingRule{{Key: key, Action: "proxy", Kind: "site", Source: "geosite:[redacted]"}}
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/routing", nil).Body.String()
	if !strings.Contains(page, `name="rule" value="`+key+`"`) || strings.Contains(page, `value="`+key+`" checked`) {
		t.Fatal("the redacted rule did not retain the legacy disabled state")
	}
	w := setupRequest(h, "/routing", url.Values{
		"rev": {formField(t, page, "rev")}, "mode": {"provider"}, "rule": {key}, "enabled": {key},
	})
	if w.Code != http.StatusSeeOther || len(f.cfg.ProviderRules.Disabled) != 0 {
		t.Fatalf("re-enabling the redacted rule returned HTTP %d with %d disabled keys", w.Code, len(f.cfg.ProviderRules.Disabled))
	}
}

func TestRoutingRefusesWithheldRules(t *testing.T) {
	for _, off := range []bool{false, true} {
		f := newRoutingFixture()
		f.cfg.Networks[0].Default = model.TargetDirect
		f.cfg.ProviderRules.Off = off
		f.rules = RoutingRules{Source: "sample", State: "withheld"}
		if off {
			f.rules = RoutingRules{State: "off"}
			f.subs[0].RulesWithheld = true
		}
		h := New(f, setupTestOptions(RoleManage))
		page := setupRequest(h, "/routing", nil)
		assertContains(t, page.Body.String(), `value="provider" id="routing-mode-provider" required disabled`,
			"The provider does not supply routing rules.")
		w := setupRequest(h, "/routing", url.Values{
			"rev": {Revision(f.Config())}, "mode": {"provider"},
		})
		if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || f.cfg.Networks[0].Default != model.TargetDirect {
			t.Fatalf("withheld mode with rules off=%v returned HTTP %d with %d applies", off, w.Code, f.applies)
		}
	}
}

func TestRoutingRefusesRuleEditsAfterWithholding(t *testing.T) {
	const enabled, legacy = "proxy:geosite:youtube", "proxy:geosite:https://provider.example/private?key=synthetic"
	disabled := model.RedactedProviderRuleKey(legacy)
	for _, tc := range []struct {
		name, mode string
		switches   []string
	}{
		{name: "disable", mode: "provider"},
		{name: "reenable a redacted rule", mode: "provider", switches: []string{enabled, disabled}},
		{name: "disable while changing mode", mode: "own"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRoutingFixture()
			f.cfg.ProviderRules.Disabled = []string{legacy}
			f.rules.State = "ready"
			f.rules.Rules = append(f.rules.Rules, RoutingRule{Key: disabled, Action: "proxy", Kind: "site", Source: "geosite:[redacted]"})
			h := New(f, setupTestOptions(RoleManage))
			before := f.Config()
			page := setupRequest(h, "/routing", nil).Body.String()
			assertContains(t, page, `name="enabled" value="`+enabled+`" checked`, `name="rule" value="`+disabled+`"`)

			f.rules = RoutingRules{Source: "sample", State: "withheld"}
			f.subs[0].RulesWithheld = true
			w := setupRequest(h, "/routing", url.Values{
				"rev": {formField(t, page, "rev")}, "mode": {tc.mode},
				"rule": {enabled, disabled}, "enabled": tc.switches, "own-direct": {"draft-direct.example"},
			})
			if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(f.Config(), before) {
				t.Fatalf("withheld rule edit returned HTTP %d with %d applies", w.Code, f.applies)
			}
			assertContains(t, w.Body.String(), `role="alert"`, "The provider stopped supplying routing rules.", "draft-direct.example")
		})
	}
}

func TestRoutingRetainsSavedProviderModeWhileRulesAreWithheld(t *testing.T) {
	for _, refreshed := range []bool{false, true} {
		name := "first save with a node-only feed"
		if refreshed {
			name = "ready to withheld while the form is open"
		}
		t.Run(name, func(t *testing.T) {
			f := newRoutingFixture()
			h := New(f, setupTestOptions(RoleManage))
			id := "sample"
			if !refreshed {
				id = setupSourceID
				f.setupFixture = setupFixture{
					cfg: &model.Config{}, lan: netip.MustParsePrefix("192.0.2.0/24"),
					preview: SetupPreview{State: subscription.StateReady, NodeCount: 1, RulesState: "withheld"},
				}
				f.rules = RoutingRules{Source: id, State: "withheld"}
				f.subs[0].ID, f.subs[0].RulesWithheld = id, true
				f.status.Connections[model.ManagedTarget(id, "auto")] = ConnectionStatus{Class: stats.TargetVPN}
				if w := setupRequest(h, "/setup/enable", checkSetupLink(t, h)); w.Code != http.StatusSeeOther {
					t.Fatalf("enabling a node-only subscription returned HTTP %d", w.Code)
				}
			} else {
				f.rules.State = "ready"
			}
			const enabled, disabled = "proxy:geosite:youtube", "proxy:geosite:returned"
			f.cfg.ProviderRules.Disabled = []string{disabled, "proxy:site:held"}
			applies := f.applies
			before := f.Config()
			page := setupRequest(h, "/routing", nil)
			body := page.Body.String()
			const providerRadio = `value="provider" id="routing-mode-provider" required checked`
			assertContains(t, body, providerRadio)
			form := url.Values{"rev": {formField(t, body, "rev")}, "own-direct": {"new-direct.example"}}
			if !strings.Contains(body, providerRadio+" disabled") {
				form.Set("mode", "provider")
			}
			if refreshed {
				// A native POST from the old page includes its unchanged switches.
				assertContains(t, body, `name="rule" value="`+disabled+`"`, `name="enabled" value="`+enabled+`" checked`)
				form["rule"], form["enabled"] = []string{enabled, disabled}, []string{enabled}
			}
			f.rules = RoutingRules{Source: id, State: "withheld"}
			f.subs[0].RulesWithheld = true
			w := setupRequest(h, "/routing", form)
			if w.Code != http.StatusSeeOther || f.applies != applies+1 {
				t.Fatalf("an unrelated list save returned HTTP %d, applies %d", w.Code, f.applies)
			}
			if f.cfg.Networks[0].Default != model.DefaultProfile || !reflect.DeepEqual(before.ProviderRules, f.cfg.ProviderRules) ||
				!slices.ContainsFunc(f.cfg.Groups, func(group model.Group) bool {
					return group.Name == "own-direct" && slices.Equal(group.Entries, []string{"new-direct.example"})
				}) {
				t.Error("the list save changed the previously selected provider policy or lost the direct exception")
			}
			assertContains(t, setupRequest(h, "/routing", nil).Body.String(), providerRadio+">", "The provider does not supply routing rules.")
		})
	}
}

func TestRoutingRejectsNonVPNMainTargets(t *testing.T) {
	for _, tc := range []struct {
		kind, explanation string
		class             stats.TargetClass
	}{
		{"direct", "The main connection for the home network routes directly.", stats.TargetDirect},
		{"block", "The main connection blocks traffic.", stats.TargetBlock},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			f := newRoutingFixture()
			f.cfg.ProviderRules.Off = true
			f.cfg.Connections[0] = model.Connection{ID: "old", Type: model.ConnSingBox, Outbound: map[string]any{"type": tc.kind}}
			network := &f.cfg.Networks[0]
			network.Target, network.Default = "old", "old"
			f.cfg.Groups[0].Target = "old"
			f.status.Connections["old"] = ConnectionStatus{Class: tc.class}
			h := New(f, setupTestOptions(RoleManage))
			page := setupRequest(h, "/routing", nil)
			assertContains(t, page.Body.String(), `value="all" id="routing-mode-all" required disabled`, tc.explanation)
			if strings.Contains(page.Body.String(), "All traffic through VPN") {
				t.Errorf("named %s was labeled as a VPN", tc.kind)
			}
			w := setupRequest(h, "/routing", url.Values{"rev": {Revision(f.Config())}, "mode": {"all"}})
			if w.Code != http.StatusUnprocessableEntity || f.applies != 0 {
				t.Fatalf("non-VPN mode returned HTTP %d with %d applies", w.Code, f.applies)
			}
		})
	}
}

func TestRoutingOffersVPNModeForMixedTargetUsingDirectReserve(t *testing.T) {
	f := newRoutingFixture()
	target := f.cfg.Networks[0].Target
	f.cfg.Subscriptions[0].Fallback = model.TargetDirect
	f.subs[0].Unavailable, f.subs[0].SwitchReason = true, "fallback"
	f.status.Connections[target] = ConnectionStatus{Class: stats.TargetMixed, ActiveClass: stats.TargetDirect}
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/routing", nil)
	assertContains(t, page.Body.String(), "Traffic follows connection Example VPN", "The main connection is using its direct reserve.",
		`value="all" id="routing-mode-all" required>`)
	if strings.Contains(page.Body.String(), "All traffic through VPN") {
		t.Error("a mixed main target was advertised as VPN-only")
	}
	w := setupRequest(h, "/routing", url.Values{"rev": {Revision(f.Config())}, "mode": {"all"}})
	if w.Code != http.StatusSeeOther || f.cfg.Networks[0].Default != target {
		t.Fatalf("mixed target mode returned HTTP %d", w.Code)
	}
}

func TestRoutingReservedGroupsWithAdvancedSettingsAreReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		group model.Group
	}{
		{"disabled", model.Group{Disabled: true, Entries: []string{"old.example"}}},
		{"geo", model.Group{Countries: []string{"GB"}}},
		{"wrong target", model.Group{Target: "old", Entries: []string{"old.example"}}},
		{"entry overrides", model.Group{Entries: []string{"old.example"}, DisabledEntries: []string{"old.example"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRoutingFixture()
			group := tc.group
			group.Name = "own-vpn"
			if group.Target == "" {
				group.Target = f.cfg.Networks[0].Target
			}
			f.cfg.Groups[0] = group
			before := f.Config()
			h := New(f, setupTestOptions(RoleManage))
			page := setupRequest(h, "/routing", nil)
			assertContains(t, page.Body.String(), "This group uses advanced settings and is read-only here.")
			if !regexp.MustCompile(`<textarea id="routing-own-vpn"[^>]* disabled`).MatchString(page.Body.String()) {
				t.Error("advanced group has an enabled textarea")
			}
			w := setupRequest(h, "/routing", url.Values{
				"rev": {Revision(before)}, "mode": {"provider"}, "own-vpn": {"new.example"},
			})
			if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(f.Config(), before) {
				t.Fatalf("advanced group edit returned HTTP %d with %d applies", w.Code, f.applies)
			}
		})
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
