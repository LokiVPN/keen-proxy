package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const overviewNodeID = "123456789abcdef0123456789abcdef0"

func TestOverviewStates(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		paused, ready, down     bool
		untilExpiry             time.Duration
		status, detail, renewal string
	}{
		{name: "working", ready: true, untilExpiry: 90 * 24 * time.Hour, status: "Working", detail: "North · 42 ms", renewal: "Active"},
		{name: "expiring", ready: true, untilExpiry: 3 * 24 * time.Hour, status: "Subscription expiring", detail: "North · 42 ms", renewal: "Renew"},
		{name: "expired", ready: true, untilExpiry: -time.Hour, status: "Subscription expired", detail: "North · 42 ms", renewal: "Renew"},
		{name: "down", ready: true, down: true, untilExpiry: time.Hour, status: "No connection", detail: "No subscription node is available.", renewal: "Expiring"},
		{name: "engine down", status: "No connection", detail: "VPN routing is unavailable.", renewal: "Expired"},
		{name: "paused", paused: true, ready: true, down: true, status: "Disabled", detail: "All devices connect directly, without the VPN.", renewal: "Expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOverviewFixture()
			f.cfg.Paused, f.status.Ready = tc.paused, tc.ready
			f.subs[0].Unavailable = tc.down
			f.subs[0].Metadata.Usage.Expire = time.Now().Add(tc.untilExpiry).Unix()
			w := setupRequest(New(f, setupTestOptions(RoleManage)), "/", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("GET / returned HTTP %d", w.Code)
			}
			body := w.Body.String()
			banner, _, _ := strings.Cut(body, `aria-label="KeenProxy sections"`)
			assertContains(t, banner, ">"+tc.status+"</span>", tc.detail)
			assertContains(t, body, tc.renewal, "18 GB of 200 GB", `value="19327352832" max="214748364800"`,
				"Last updated", "Next update", "Maintenance tonight", `href="/connections/subscriptions/sample/replace"`, "Routing by Example VPN",
				"1 of 2 rules enabled", "Own site entries: 1", "KeenProxy handles 2 of 3 devices")
			if tc.renewal == "Renew" {
				assertContains(t, body, `href="https://provider.example/account"`)
			}
			if strings.Contains(body, "synthetic-token") || strings.Contains(body, "style=") {
				t.Error("overview disclosed the saved link or used inline styles")
			}
		})
	}
}

func TestOverviewIgnoresDormantProviderRules(t *testing.T) {
	f := newOverviewFixture()
	f.cfg.ProviderRules.Off = true
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/", nil)
	assertContains(t, page.Body.String(), "Follow the subscription profile")
	if strings.Contains(page.Body.String(), "Routing by Example VPN") || strings.Contains(page.Body.String(), "1 of 2 rules enabled") {
		t.Error("overview presented dormant rules as active")
	}
}

func TestOverviewStatusPrecedence(t *testing.T) {
	emptyCatalog := func(f *overviewFixture, fallback string) {
		f.cfg.Subscriptions[0].Fallback = fallback
		f.subs[0].Unavailable = true
		f.subs[0].Nodes, f.subs[0].ActiveNode = nil, ""
		network := &f.cfg.Networks[0]
		network.Mode, network.Default = model.ModeFull, ""
		delete(f.status.Connections, network.Target)
	}
	rawTarget := func(f *overviewFixture, outbound map[string]any, class stats.TargetClass, available bool) {
		conn := &f.cfg.Connections[0]
		conn.Type, conn.Link, conn.Outbound = model.ConnSingBox, "", outbound
		f.cfg.Networks[0].Target = conn.ID
		f.status.Connections[conn.ID] = ConnectionStatus{Class: class, Checked: true, Available: available}
	}
	direct := map[string]any{"type": "direct"}
	mixed := map[string]any{"type": "selector", "default": "backup", "outbounds": []string{model.TargetDirect, "backup"}}
	reject := model.Connection{ID: "reject", Type: model.ConnSingBox, Outbound: map[string]any{"type": "block"}}
	for _, tc := range []struct {
		name, chip, detail string
		arrange            func(*overviewFixture)
	}{
		{"paused before engine and reserve", "Disabled", "All devices connect directly, without the VPN.", func(f *overviewFixture) {
			emptyCatalog(f, model.TargetDirect)
			f.cfg.Paused, f.status.Ready = true, false
		}},
		{"engine before failed probe", "No connection", "VPN routing is unavailable.", func(f *overviewFixture) {
			f.cfg.Networks[0].Target, f.status.Ready = "old", false
		}},
		{"no home policy", "No connection", "No home network configured.", func(f *overviewFixture) {
			f.cfg.Networks = nil
		}},
		{"home VPN off before failed probe", "Home VPN off", "Devices that follow the home policy connect directly.", func(f *overviewFixture) {
			f.cfg.Networks[0].Mode, f.cfg.Networks[0].Target = model.ModeOff, "old"
		}},
		{"no main target", "No connection", "Choose a main connection.", func(f *overviewFixture) {
			f.cfg.Networks[0].Target = ""
		}},
		{"checked direct target fails", "No connection", "The main connection is unavailable.", func(f *overviewFixture) {
			rawTarget(f, direct, stats.TargetDirect, false)
		}},
		{"mixed selector fails", "No connection", "The main connection is unavailable.", func(f *overviewFixture) {
			rawTarget(f, mixed, stats.TargetMixed, false)
		}},
		{"subscription node fails before switching to its reserve", "No connection", "No subscription node is available.", func(f *overviewFixture) {
			f.cfg.Subscriptions[0].Fallback = model.TargetDirect
			f.subs[0].Nodes[0].Health = connectionUnavailable
		}},
		{"active reserve member fails", "No connection", "The reserve connection is unavailable.", func(f *overviewFixture) {
			emptyCatalog(f, "backup")
			f.cfg.Connections[1].Fallback = "old"
			f.status.Connections["backup"] = ConnectionStatus{Class: stats.TargetVPN, Active: "old", Checked: true, Available: true}
		}},
		{"empty catalog uses unchecked direct reserve", "Direct connection", "The main connection is using its direct reserve.", func(f *overviewFixture) {
			emptyCatalog(f, model.TargetDirect)
		}},
		{"auto switches to direct with catalog still present", "Direct connection", "The main connection is using its direct reserve.", func(f *overviewFixture) {
			f.cfg.Subscriptions[0].Fallback = model.TargetDirect
			f.subs[0].Unavailable, f.subs[0].SwitchReason, f.subs[0].ActiveNode = true, "fallback", ""
			f.subs[0].Nodes[0].Health = connectionUnavailable
			f.status.Connections[f.cfg.Networks[0].Target] = ConnectionStatus{Class: stats.TargetMixed}
		}},
		{"empty catalog uses named reserve", "Reserve connection", "Using reserve Cabin.", func(f *overviewFixture) {
			emptyCatalog(f, "backup")
		}},
		{"unchecked reserve member stays in use after its primary fails", "Reserve connection", "Using reserve Cabin.", func(f *overviewFixture) {
			emptyCatalog(f, "backup")
			f.cfg.Connections[1].Fallback = "old"
			f.status.Connections["backup"] = ConnectionStatus{Class: stats.TargetVPN, Active: "old", Checked: true}
			f.status.Connections["old"] = ConnectionStatus{Class: stats.TargetVPN}
		}},
		{"empty catalog with built-in blocking fallback", "No connection", "No subscription node is available.", func(f *overviewFixture) {
			emptyCatalog(f, model.TargetBlock)
		}},
		{"empty catalog with named blocking reserve", "No connection", "No subscription node is available.", func(f *overviewFixture) {
			emptyCatalog(f, reject.ID)
			f.cfg.Connections = append(f.cfg.Connections, reject)
			f.status.Connections[reject.ID] = ConnectionStatus{Class: stats.TargetBlock}
		}},
		{"empty catalog with blocked reserve chain", "No connection", "No subscription node is available.", func(f *overviewFixture) {
			emptyCatalog(f, "backup")
			f.cfg.Connections[1].Disabled = true
			f.status.Connections["backup"] = ConnectionStatus{Active: model.TargetBlock}
		}},
		{"manual failover is blocked", "No connection", "The main connection is unavailable.", func(f *overviewFixture) {
			f.cfg.Networks[0].Target = "backup"
			f.status.Connections["backup"] = ConnectionStatus{Active: model.TargetBlock}
		}},
		{"selector with only a blocking leaf", "No connection", "The main connection is unavailable.", func(f *overviewFixture) {
			f.cfg.Networks[0].Target = "old"
			conn := &f.cfg.Connections[0]
			conn.Type, conn.Link = model.ConnSingBox, ""
			conn.Outbound = map[string]any{"type": "selector", "outbounds": []string{reject.ID}}
			f.cfg.Connections = append(f.cfg.Connections, reject)
			f.status.Connections[conn.ID] = ConnectionStatus{Class: stats.TargetBlock}
		}},
		{"direct classification", "Direct connection", "The main connection for the home network routes directly.", func(f *overviewFixture) {
			rawTarget(f, direct, stats.TargetDirect, true)
		}},
		{"expired subscription", "Subscription expired", "North \u00b7 42 ms", func(f *overviewFixture) {
			f.subs[0].Metadata.Usage.Expire = time.Now().Add(-time.Hour).Unix()
		}},
		{"expiry warning on a working subscription", "Subscription expiring", "North \u00b7 42 ms", func(f *overviewFixture) {
			f.subs[0].Metadata.Usage.Expire = time.Now().Add(time.Hour).Unix()
		}},
		{"mixed classification", "Connection routing", "Traffic follows connection Office", func(f *overviewFixture) {
			rawTarget(f, mixed, stats.TargetMixed, true)
		}},
		{"VPN classification", "Working", "Cabin \u00b7 35 ms", func(f *overviewFixture) {
			f.cfg.Networks[0].Target = "backup"
		}},
		{"awaiting first probe", "Checking connection", "Cabin \u00b7 Not checked", func(f *overviewFixture) {
			f.cfg.Networks[0].Target = "backup"
			f.status.Connections["backup"] = ConnectionStatus{Class: stats.TargetVPN}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOverviewFixture()
			tc.arrange(f)
			w := setupRequest(New(f, setupTestOptions(RoleView)), "/", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("GET / returned HTTP %d", w.Code)
			}
			_, banner, _ := strings.Cut(w.Body.String(), `<div class="overview-status">`)
			banner, _, _ = strings.Cut(banner, `</div>`)
			assertContains(t, banner, ">"+tc.chip+"</span>", tc.detail+"</p>")
		})
	}
}

func TestOverviewTargets(t *testing.T) {
	for _, tc := range []struct{ name, target, defaultTarget string }{
		{"auto", model.ManagedTarget("sample", "auto"), model.DefaultProfile},
		{"round robin", model.ManagedTarget("sample", model.SubscriptionRoundRobin), model.TargetDirect},
		{"by site", model.ManagedTarget("sample", model.SubscriptionConsistentHash), "old"},
		{"by session", model.ManagedTarget("sample", model.SubscriptionStickySession), ""},
		{"pinned", model.ManagedTarget("sample", overviewNodeID), "old"},
		{"manual", "backup", "old"},
		{"different default", model.ManagedTarget("sample", "auto"), "backup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOverviewFixture()
			f.cfg.Paused = true
			f.cfg.Networks[0].Target, f.cfg.Networks[0].Default = "old", tc.defaultTarget
			f.cfg.Groups[0].Target = "old"
			want := f.Config()
			want.Networks[0].Target, want.Groups[0].Target = tc.target, tc.target
			if tc.defaultTarget == "old" {
				want.Networks[0].Default = tc.target
			}
			h := New(f, setupTestOptions(RoleManage))
			body := setupRequest(h, "/", nil).Body.String()
			assertContains(t, body, `<optgroup label="Example VPN">`, `<optgroup label="Manual connections">`,
				"North · 42 ms", "Cabin · WireGuard · 35 ms", "Office · VLESS · No response", "Office SOCKS · SOCKS · Disabled",
				`value="`+tc.target+`"`)
			w := setupRequest(h, "/overview/connection", url.Values{"rev": {formField(t, body, "rev")}, "target": {tc.target}})
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" || f.applies != 1 {
				t.Fatalf("changing the main connection returned HTTP %d with %d applies", w.Code, f.applies)
			}
			if !reflect.DeepEqual(f.Config(), want) {
				t.Error("the result did not preserve the rest of the applied configuration under R31")
			}
		})
	}
}

func TestOverviewShowsAndRefreshesEachSubscription(t *testing.T) {
	f := newOverviewFixture()
	addSecondSubscription(f)
	f.cfg.Subscriptions = append(f.cfg.Subscriptions, subscription.Source{ID: "sub3", URL: "https://third.example/list"})
	second, third := &f.subs[1], f.cfg.Subscriptions[2]
	second.Metadata.Usage = &subscription.Usage{Download: 5 << 30, Total: 80 << 30, Expire: time.Now().Add(-time.Hour).Unix()}
	latency := int64(27)
	second.Nodes = []SubscriptionNode{{ID: overviewNodeID, Name: "South", Health: connectionAvailable, LatencyMS: &latency}}
	network := &f.cfg.Networks[0]
	network.Target = model.ManagedTarget("sub2", "auto")
	network.Default, f.cfg.Groups[0].Target = network.Target, network.Target
	f.cfg.ProviderRules.Source, f.cfg.ProviderRules.Off = third.ID, true
	f.status.Connections[network.Target] = ConnectionStatus{Class: stats.TargetVPN}
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/", nil)
	body := page.Body.String()
	_, cards, _ := strings.Cut(body, `aria-labelledby="subscription-title">`)
	cards, _, _ = strings.Cut(cards, `aria-labelledby="connection-title">`)
	for _, id := range []string{"sub2", "sample", third.ID} {
		assertContains(t, cards, `id="overview-subscription-label-`+id+`"`, `name="source" value="`+id+`"`,
			`href="/connections/subscriptions/`+id+`/replace"`)
	}
	if strings.Index(cards, `id="overview-subscription-label-sub2"`) > strings.Index(cards, `id="overview-subscription-label-sample"`) ||
		strings.Index(cards, `id="overview-subscription-label-sample"`) > strings.Index(cards, `id="overview-subscription-label-sub3"`) {
		t.Error("cards did not put the main subscription first and keep the rest in configuration order")
	}
	assertContains(t, cards, "5 GB of 80 GB", "18 GB of 200 GB", ">Expired</span>", ">Active</span>", ">Pending</span>")
	assertContains(t, body, "Example VPN · sub2 · South · 27 ms", `>Subscription expired</span>`)
	_, options, _ := strings.Cut(body, `<optgroup label="Example VPN · sub2">`)
	options, _, _ = strings.Cut(options, `</optgroup>`)
	for _, mode := range []string{"auto", model.SubscriptionRoundRobin, model.SubscriptionConsistentHash, model.SubscriptionStickySession, overviewNodeID} {
		assertContains(t, options, `value="`+model.ManagedTarget("sub2", mode)+`"`)
	}
	assertContains(t, options, "South · 27 ms")
	assertContains(t, body, `<optgroup label="Example VPN · sample">`, `<optgroup label="Manual connections">`)

	rev := formField(t, body, "rev")
	refresh := setupRequest(h, "/overview/refresh", url.Values{"rev": {rev}, "source": {"sub2"}})
	if refresh.Code != http.StatusSeeOther || !reflect.DeepEqual(f.refreshes, []string{"sub2"}) || f.applies != 0 {
		t.Fatalf("refresh returned HTTP %d, refreshes %v, applies %d", refresh.Code, f.refreshes, f.applies)
	}
	for _, sources := range [][]string{nil, {""}, {"missing"}, {"sample", "sub2"}} {
		post := setupRequest(h, "/overview/refresh", url.Values{"rev": {rev}, "source": sources})
		if post.Code != http.StatusUnprocessableEntity || !reflect.DeepEqual(f.refreshes, []string{"sub2"}) {
			t.Fatalf("refresh with sources %q returned HTTP %d, refreshes %v", sources, post.Code, f.refreshes)
		}
	}

	// R31 moves the managed targets while the source of routing rules stays independent.
	pinned := model.ManagedTarget("sample", overviewNodeID)
	want := f.Config()
	want.Networks[0].Target, want.Networks[0].Default, want.Groups[0].Target = pinned, pinned, pinned
	change := setupRequest(h, "/overview/connection", url.Values{"rev": {rev}, "target": {pinned}})
	if change.Code != http.StatusSeeOther || f.applies != 1 || !reflect.DeepEqual(f.Config(), want) {
		t.Fatalf("main connection change returned HTTP %d with %d applies", change.Code, f.applies)
	}
}

func TestOverviewNamesTheSubscriptionUsingAReserve(t *testing.T) {
	f := newOverviewFixture()
	addSecondSubscription(f)
	f.cfg.Networks[0].Target = model.ManagedTarget("sub2", "auto")
	f.cfg.Subscriptions[1].Fallback = "backup"
	f.subs[1].Unavailable, f.subs[1].SwitchReason = true, "fallback"
	h := New(f, setupTestOptions(RoleManage))
	assertContains(t, setupRequest(h, "/", nil).Body.String(), `>Reserve connection</span>`,
		"Example VPN · sub2 · Using reserve Cabin.", "Current connection · Example VPN · sub2 · Cabin")

	f.status.Connections["backup"] = ConnectionStatus{Class: stats.TargetVPN, Checked: true}
	assertContains(t, setupRequest(h, "/", nil).Body.String(), `>No connection</span>`,
		"Example VPN · sub2 · The reserve connection is unavailable.")
}

func TestOverviewLeavesReadOnlyOwnVPNGroupsInPlace(t *testing.T) {
	main := model.ManagedTarget("sample", "auto")
	for _, tc := range []struct {
		name   string
		groups []model.Group
	}{
		{"dedicated target", []model.Group{{Name: "own-vpn", Target: "old", Entries: []string{"dedicated.example"}}}},
		{"country group", []model.Group{{Name: "own-vpn", Target: main, Countries: []string{"GB"}}}},
		{"overridden entry", []model.Group{{Name: "own-vpn", Target: main, Entries: []string{"saved.example"}, DisabledEntries: []string{"saved.example"}}}},
		{"duplicate names", []model.Group{
			{Name: "own-vpn", Target: main, Entries: []string{"saved.example"}},
			{Name: "ordinary", Target: "old", Entries: []string{"middle.example"}},
			{Name: "own-vpn", Target: "old", Entries: []string{"dedicated.example"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOverviewFixture()
			f.cfg.Groups = tc.groups
			f.cfg.Networks[0].Default = main
			before := f.Config()
			h := New(f, setupTestOptions(RoleManage))
			w := setupRequest(h, "/overview/connection", url.Values{"rev": {Revision(before)}, "target": {"backup"}})
			if w.Code != http.StatusSeeOther || f.cfg.Networks[0].Target != "backup" || f.cfg.Networks[0].Default != "backup" {
				t.Fatalf("main connection change returned HTTP %d, Home %+v", w.Code, f.cfg.Networks[0])
			}
			if !reflect.DeepEqual(before.Groups, f.cfg.Groups) {
				t.Error("main connection change rewrote the targets or order of read-only groups")
			}
		})
	}
}

func TestOverviewStatusUsesTheSelectedConnection(t *testing.T) {
	f := newOverviewFixture()
	network := &f.cfg.Networks[0]
	network.Target = model.ManagedTarget("sample", model.SubscriptionStickySession)
	f.status.Connections[network.Target] = ConnectionStatus{Class: stats.TargetVPN}
	f.cfg.Subscriptions[0].Fallback = "backup"
	eligible := 0
	f.subs[0].BalanceEligible = &eligible
	h := New(f, setupTestOptions(RoleManage))
	assertContains(t, setupRequest(h, "/", nil).Body.String(), `>Reserve connection</span>`, "Using reserve Cabin.")
	eligible = 2
	assertContains(t, setupRequest(h, "/", nil).Body.String(), `>Working</span>`, "Available nodes: 2")
	network.Target = "backup"
	f.subs[0].Unavailable = true
	f.subs[0].Metadata.Usage.Expire = time.Now().Add(-time.Hour).Unix()
	assertContains(t, setupRequest(h, "/", nil).Body.String(), `>Working</span>`, "Cabin · 35 ms", `>Expired</span>`)
}

func TestOverviewOmitsBlockingReserveName(t *testing.T) {
	f := newOverviewFixture()
	f.cfg.Subscriptions[0].Fallback = model.TargetBlock
	f.subs[0].Unavailable = true
	f.subs[0].Nodes, f.subs[0].ActiveNode = nil, ""
	delete(f.status.Connections, f.cfg.Networks[0].Target)

	body := setupRequest(New(f, setupTestOptions(RoleView)), "/", nil).Body.String()
	assertContains(t, body, `>No connection</span>`, "No subscription node is available.")
	if strings.Contains(body, "Using reserve ") || strings.Contains(body, "Current connection · block") {
		t.Error("overview named a reserve connection for the blocking fallback")
	}
}

func TestOverviewKeepsTargetClassWhileFailoverIsBlocked(t *testing.T) {
	f := newOverviewFixture()
	network := &f.cfg.Networks[0]
	network.Mode, network.Target = model.ModeFull, "backup"
	f.status.Connections["backup"] = ConnectionStatus{Class: stats.TargetVPN, Active: model.TargetBlock}
	body := setupRequest(New(f, setupTestOptions(RoleView)), "/", nil).Body.String()
	assertContains(t, body, `>No connection</span>`, `<p class="clip">All traffic through VPN</p>`)
}

func TestOverviewDirectAndOffPolicies(t *testing.T) {
	for _, tc := range []struct {
		name, target, active, chip string
		mode                       model.Mode
	}{
		{"full direct", model.TargetDirect, "", "Direct connection", model.ModeFull},
		{"direct reserve", "backup", model.TargetDirect, "Direct connection", model.ModeFull},
		{"off with a saved VPN", "backup", "", "Home VPN off", model.ModeOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOverviewFixture()
			f.cfg.Networks[0].Mode, f.cfg.Networks[0].Target = tc.mode, tc.target
			if tc.active != "" {
				f.status.Connections[tc.target] = ConnectionStatus{Active: tc.active, Class: stats.TargetDirect}
			}
			body := setupRequest(New(f, setupTestOptions(RoleView)), "/", nil).Body.String()
			banner, _, _ := strings.Cut(body, `aria-label="KeenProxy sections"`)
			assertContains(t, banner, ">"+tc.chip+"</span>")
			assertContains(t, body, "KeenProxy handles 2 of 3 devices", "New devices connect directly by default.")
			for _, claim := range []string{">Working</span>", "All traffic through VPN", "devices use VPN routing"} {
				if strings.Contains(body, claim) {
					t.Errorf("direct or off policy was presented as VPN routing: %q", claim)
				}
			}
		})
	}
}

func TestOverviewShowsFailedRefreshWithCachedNodes(t *testing.T) {
	f := newOverviewFixture()
	f.subs[0].State = subscription.StateHTTPError
	body := setupRequest(New(f, setupTestOptions(RoleView)), "/", nil).Body.String()
	assertContains(t, body, "Last update failed", "Last updated", "Next update")
	if strings.Contains(body, ">Active</span>") {
		t.Error("a cached catalog hid the most recent refresh failure")
	}
}

func TestOverviewPauseRoundTrip(t *testing.T) {
	f := newOverviewFixture()
	h := New(f, setupTestOptions(RoleManage))
	original := f.Config()
	for _, enabled := range []bool{false, true} {
		page := setupRequest(h, "/", nil)
		body := page.Body.String()
		assertContains(t, body, `action="/overview/pause"`, `role="switch"`, `data-autosubmit`, `type="submit"`)
		form := url.Values{"rev": {formField(t, body, "rev")}}
		if enabled {
			form.Set("enabled", "1")
		}
		post := setupRequest(h, "/overview/pause", form)
		if post.Code != http.StatusSeeOther || post.Header().Get("Location") != "/" {
			t.Fatalf("switch returned HTTP %d to %q", post.Code, post.Header().Get("Location"))
		}
		want := original.Clone()
		want.Paused = !enabled
		if !reflect.DeepEqual(f.Config(), want) {
			t.Fatalf("switch %t should change only Paused", enabled)
		}
		get := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, cookie := range post.Result().Cookies() {
			get.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, get)
		assertContains(t, w.Body.String(), "Settings saved")
		if strings.Contains(w.Body.String(), `value="1" checked`) != enabled {
			t.Error("the switch does not reflect the applied configuration")
		}
	}
}

func TestOverviewRejectsViewWritesAndStaleForms(t *testing.T) {
	for _, path := range []string{"/overview/pause", "/overview/connection", "/overview/refresh"} {
		for _, tc := range []struct {
			role Role
			rev  string
			code int
		}{
			{RoleView, "current", http.StatusForbidden},
			{RoleManage, "stale", http.StatusConflict},
		} {
			f := newOverviewFixture()
			h := New(f, setupTestOptions(tc.role))
			rev := tc.rev
			if tc.role == RoleView {
				page := setupRequest(h, "/", nil)
				rev = formField(t, page.Body.String(), "rev")
				assertContains(t, page.Body.String(), "View only", `data-autosubmit disabled`, `type="submit" disabled`,
					`<button class="btn soft" aria-describedby="overview-subscription-label-sample" type="button" disabled>Replace link</button>`)
			}
			post := setupRequest(h, path, url.Values{"rev": {rev}, "target": {"backup"}})
			if post.Code != tc.code || f.applies != 0 || len(f.refreshes) != 0 {
				t.Fatalf("POST %s as %v: HTTP %d, applies %d, refreshes %v", path, tc.role, post.Code, f.applies, f.refreshes)
			}
			if tc.role == RoleManage {
				assertContains(t, post.Body.String(), "Settings changed in another window", `name="rev" value="`+Revision(f.Config())+`"`)
			}
		}
	}
}

func TestOverviewRejectsTargetsOutsideEnabledOptions(t *testing.T) {
	f := newOverviewFixture()
	f.subs[0].Nodes = append(f.subs[0].Nodes, SubscriptionNode{ID: strings.Repeat("f", 32), Name: "Far", Health: "unavailable"})
	h := New(f, setupTestOptions(RoleManage))
	for _, target := range []string{"", model.TargetDirect, "disabled", model.ManagedTarget("other", "auto"),
		model.ManagedTarget("sample", strings.Repeat("a", 32)), model.ManagedTarget("sample", strings.Repeat("f", 32))} {
		post := setupRequest(h, "/overview/connection", url.Values{"rev": {Revision(f.Config())}, "target": {target}})
		if post.Code != http.StatusUnprocessableEntity || f.applies != 0 {
			t.Fatalf("POST for target %q returned HTTP %d and made %d applies", target, post.Code, f.applies)
		}
	}
}

func TestOverviewRefreshAndConcurrentApply(t *testing.T) {
	f := newOverviewFixture()
	f.cfg.Subscriptions = append(f.cfg.Subscriptions, subscription.Source{ID: "extra", URL: "https://second.example/config"})
	h := New(f, setupTestOptions(RoleManage))
	form := url.Values{"rev": {Revision(f.Config())}, "source": {"sample"}}
	w := setupRequest(h, "/overview/refresh", form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" ||
		!reflect.DeepEqual(f.refreshes, []string{"sample"}) || f.applies != 0 {
		t.Fatalf("refresh returned HTTP %d with refreshes %v and %d applies", w.Code, f.refreshes, f.applies)
	}
	f.refreshErr = model.ErrConfigChanged
	if w := setupRequest(h, "/overview/refresh", form); w.Code != http.StatusConflict || len(f.refreshes) != 1 {
		t.Fatalf("racing refresh returned HTTP %d with refreshes %v", w.Code, f.refreshes)
	}
	f.saveErr = model.ErrConfigChanged
	w = setupRequest(h, "/overview/pause", form)
	if w.Code != http.StatusConflict || f.cfg.Paused {
		t.Fatalf("racing pause returned HTTP %d, paused %t", w.Code, f.cfg.Paused)
	}
	f.saveErr = &model.AppliedUnsavedError{Err: errors.New(setupTestURL)}
	w = setupRequest(h, "/overview/pause", form)
	if w.Code != http.StatusInternalServerError || !f.cfg.Paused {
		t.Fatalf("applied-but-unsaved pause returned HTTP %d, paused %t", w.Code, f.cfg.Paused)
	}
	assertContains(t, w.Body.String(), "The new settings are active", "All devices connect directly")
	if strings.Contains(w.Body.String(), "synthetic-token") {
		t.Error("persistence error disclosed the subscription link")
	}
}

func TestOverviewTrafficFragmentAndEmptyStates(t *testing.T) {
	f := newOverviewFixture()
	f.cfg.Subscriptions, f.cfg.ProviderRules, f.cfg.Networks, f.subs = nil, nil, nil, nil
	f.cfg.Clients = nil
	f.status = OverviewStatus{Ready: true}
	h := New(f, setupTestOptions(RoleView))
	w := setupRequest(h, "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("manual-only overview returned HTTP %d", w.Code)
	}
	assertContains(t, w.Body.String(), "No subscription configured", "No home network configured", "No LAN devices detected",
		`data-fragment="/fragments/traffic"`, "No traffic samples yet", `href="/routing"`, `href="/devices"`)
	for _, path := range []string{"/routing", "/devices"} {
		page := setupRequest(h, path, nil)
		if page.Code != http.StatusOK {
			t.Fatalf("linked tab %s returned HTTP %d", path, page.Code)
		}
		assertContains(t, page.Body.String(), `href="`+path+`" aria-current="page"`)
		if path == "/devices" {
			assertContains(t, page.Body.String(), "No home network configured", "No LAN devices detected")
		}
	}
	now := time.Now().Add(-time.Second)
	f.traffic = []stats.Point{{T: now.Add(-time.Minute).UnixMilli(), Down: 16e6, Up: 2e6}, {T: now.UnixMilli(), Down: 24.8e6, Up: 2.1e6}}
	w = setupRequest(h, "/fragments/traffic", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("traffic fragment returned HTTP %d", w.Code)
	}
	assertPageHeaders(t, w.Result(), "en")
	assertContains(t, w.Body.String(), "Incoming 24.8 Mbit/s", "Outgoing 2.1 Mbit/s", `<path class="rx-l"`, `preserveAspectRatio="none"`)
	if strings.Contains(w.Body.String(), "<!doctype") || strings.Contains(w.Body.String(), `data-fragment=`) {
		t.Error("fragment should contain only the traffic content")
	}
	denied := setupRequest(New(f, setupTestOptions(RoleDeny)), "/fragments/traffic", nil)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unauthorized fragment returned HTTP %d", denied.Code)
	}
}

func TestOverviewEscapesDisplayStrings(t *testing.T) {
	f := newOverviewFixture()
	f.subs[0].Metadata.Title = `<name>"`
	f.subs[0].Metadata.Announce = `<script>alert(1)</script>`
	f.subs[0].Nodes[0].Name = `<option>"`
	f.cfg.Connections[0].Name = `</option>"`
	page := setupRequest(New(f, setupTestOptions(RoleView)), "/", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("overview returned HTTP %d", page.Code)
	}
	assertContains(t, page.Body.String(), `&lt;name&gt;&#34;`, `&lt;script&gt;alert(1)&lt;/script&gt;`, `&lt;option&gt;&#34;`, `&lt;/option&gt;&#34;`)
	if strings.Contains(page.Body.String(), `<script>alert(1)</script>`) || strings.Contains(page.Body.String(), "synthetic-token") {
		t.Error("overview rendered raw provider markup or a saved secret")
	}
}

type overviewFixture struct {
	setupFixture
	status     OverviewStatus
	subs       []AppliedSubscription
	traffic    []stats.Point
	refreshes  []string
	refreshErr error
}

func (f *overviewFixture) OverviewStatus() OverviewStatus       { return f.status }
func (f *overviewFixture) Subscriptions() []AppliedSubscription { return f.subs }
func (f *overviewFixture) TrafficSeries() []stats.Point         { return f.traffic }

func (f *overviewFixture) Apply(ctx context.Context, cfg *model.Config, rev string) error {
	if errors.Is(f.saveErr, model.ErrConfigChanged) {
		return f.saveErr
	}
	return f.setupFixture.Apply(ctx, cfg, rev)
}

func (f *overviewFixture) ApplyUnlessRulesWithheld(ctx context.Context, cfg *model.Config, revision, _ string) error {
	return f.Apply(ctx, cfg, revision)
}

func (f *overviewFixture) RefreshSubscription(id, revision string) error {
	if revision != Revision(f.Config()) {
		return model.ErrConfigChanged
	}
	if f.refreshErr != nil {
		return f.refreshErr
	}
	f.refreshes = append(f.refreshes, id)
	return nil
}

func newOverviewFixture() *overviewFixture {
	now := time.Now()
	latency := int64(42)
	cfg := &model.Config{Subscriptions: []subscription.Source{{ID: "sample", URL: setupTestURL}}}
	cfg.RouteHomeThroughSubscription("sample", netip.MustParsePrefix("192.0.2.0/24"))
	cfg.Connections = []model.Connection{
		{ID: "old", Name: "Office", Type: model.ConnLink, Link: "vless://synthetic-token@example.test"},
		{ID: "backup", Name: "Cabin", Type: model.ConnWireGuard},
		{ID: "disabled", Name: "Office SOCKS", Type: model.ConnLink, Link: "socks5://example.test", Disabled: true},
	}
	cfg.Groups = []model.Group{
		{Name: "own-vpn", Target: cfg.Networks[0].Target, Entries: []string{"local.example"}},
		{Name: "own-direct", Target: model.TargetDirect},
		{Name: "additional", Target: "old"},
	}
	cfg.Networks = append(cfg.Networks, model.Network{Name: "Other", CIDR: "198.51.100.0/24", Mode: model.ModeFull, Target: "old"})
	cfg.Clients = []model.Client{{MAC: "02:00:00:00:00:01", Mode: model.ModeFull, Target: "old"}}
	return &overviewFixture{
		setupFixture: setupFixture{cfg: cfg},
		status: OverviewStatus{Ready: true, Devices: 3, ManagedDevices: 2, RulesState: "ready", RulesActive: 1, RulesTotal: 2,
			Connections: map[string]ConnectionStatus{
				model.ManagedTarget("sample", "auto"): {Class: stats.TargetVPN},
				"old":                                 {Class: stats.TargetVPN, Checked: true},
				"backup":                              {Class: stats.TargetVPN, Checked: true, Available: true, LatencyMS: 35},
			},
		},
		subs: []AppliedSubscription{{
			ID: "sample", State: subscription.StateReady, ActiveNode: overviewNodeID,
			Metadata: subscription.Metadata{Title: "Example VPN", Announce: "Maintenance tonight", ProfileURL: "https://provider.example/account",
				Usage: &subscription.Usage{Download: 18 << 30, Total: 200 << 30, Expire: now.Add(90 * 24 * time.Hour).Unix()}},
			Nodes:       []SubscriptionNode{{ID: overviewNodeID, Name: "North", Health: "available", LatencyMS: &latency}},
			LastSuccess: now.Add(-time.Hour), NextRefresh: now.Add(11 * time.Hour),
		}},
	}
}
