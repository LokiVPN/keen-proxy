package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	deviceFullMAC  = "02:00:00:00:00:01"
	deviceTVMAC    = "02:00:00:00:00:02"
	deviceHomeMAC  = "02:00:00:00:00:03"
	deviceGuestMAC = "02:00:00:00:00:04"
)

func TestDevicesRenderConfiguredClients(t *testing.T) {
	f := newDevicesFixture(t)
	f.cfg.Clients[2].Name = " \t "
	h := New(f, setupTestOptions(RoleManage))
	w := setupRequest(h, "/devices", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /devices = %d", w.Code)
	}
	assertPageHeaders(t, w.Result(), "en")
	body := w.Body.String()
	assertContains(t, body, `href="/devices" aria-current="page"`, `Office &lt;script&gt;`,
		"192.0.2.11", "Full tunnel", "New device", "MAC "+deviceHomeMAC, "198.51.100.14")
	if strings.Contains(body, "Office <script>") || strings.Contains(body, "style=") {
		t.Fatal("device page contains unescaped markup or an inline style")
	}
	form := readDevicesForm(t, body)
	if strings.Count(body, "data-device-switch") != 4 || !slices.Equal(form["split"], []string{deviceHomeMAC}) ||
		!slices.Equal(form["full"], []string{deviceFullMAC}) || form.Get("new") != "1" {
		t.Fatalf("unexpected device controls: %v", form)
	}
}

func TestDevicesSavePinsInheritedModesAndPreservesClientFields(t *testing.T) {
	f := newDevicesFixture(t)
	f.cfg.Paused = true
	want := f.Config()
	want.Networks[0].Mode = model.ModeOff
	want.Clients[1].Mode = model.ModeSplit // TV switched on explicitly.
	want.Clients[2].Mode = model.ModeSplit // Inherited from Home when the form opened.
	want.Clients[3].Mode = model.ModeOff   // Inherited from Guest.
	h := New(f, setupTestOptions(RoleManage))
	form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	form.Del("new")
	form.Add("split", deviceTVMAC)
	w := setupRequest(h, "/devices", form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/devices" || f.applies != 1 {
		t.Fatalf("Save = HTTP %d, location %q, Apply calls %d", w.Code, w.Header().Get("Location"), f.applies)
	}
	if got := f.Config(); !reflect.DeepEqual(want, got) {
		t.Fatalf("saved clients %+v and networks %+v, want %+v and %+v", got.Clients, got.Networks, want.Clients, want.Networks)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("Save did not set a flash")
	}
	reloaded := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	if reloaded.Has("new") || len(reloaded["split"]) != 2 || !slices.Contains(reloaded["split"], deviceHomeMAC) ||
		!slices.Contains(reloaded["split"], deviceTVMAC) || reloaded.Get("full") != deviceFullMAC {
		t.Fatalf("persisted switches: %v", reloaded)
	}
}

func TestDevicesKeepsInheritedFullRouteWhenHomeTurnsOff(t *testing.T) {
	const mac, ip, fullSet = "02:00:00:00:00:25", "192.0.2.25", "clients-full-manual"
	f := newDevicesFixture(t)
	f.cfg.Clients = nil
	home := &f.cfg.Networks[0]
	home.Mode, home.Target, home.Default = model.ModeFull, "manual", ""
	f.discovered = []DiscoveredDevice{{MAC: mac, IP: ip, Name: "Laptop"}}
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/devices", nil)
	form := readDevicesForm(t, page.Body.String())
	form.Del("new")
	if w := setupRequest(h, "/devices", form); w.Code != http.StatusSeeOther || f.applies != 1 {
		t.Fatalf("Home Save = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
	if f.cfg.Networks[0].Mode != model.ModeOff || f.cfg.Networks[0].Target != "manual" ||
		!slices.Equal(f.cfg.Clients, []model.Client{{MAC: mac, Mode: model.ModeFull}}) {
		t.Errorf("Home is %+v, saved laptop is %+v", f.cfg.Networks[0], f.cfg.Clients)
	}
	assertContains(t, page.Body.String(), "Full tunnel")
	assertDeviceOutbound(t, f.Config(), mac, ip, fullSet, "manual")
}

func TestDevicesRejectsFullPinAfterAddressMoves(t *testing.T) {
	const mac = "02:00:00:00:00:25"
	for _, ip := range []string{"203.0.113.25", "198.51.100.25"} {
		t.Run(ip, func(t *testing.T) {
			f := newDevicesFixture(t)
			f.cfg.Clients = nil
			f.cfg.Networks[0].Mode = model.ModeFull
			// A guest split default cannot supply a Full tunnel's target.
			f.cfg.Networks[1].Target, f.cfg.Networks[1].Default = "", "manual"
			f.discovered = []DiscoveredDevice{{MAC: mac, IP: "192.0.2.25", Name: "Laptop"}}
			before := f.Config()
			h := New(f, setupTestOptions(RoleManage))
			form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
			if form.Get("full") != mac {
				t.Fatal("the laptop did not inherit Full")
			}
			form.Del("new")
			f.discovered[0].IP = ip
			w := setupRequest(h, "/devices", form)
			if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(before, f.Config()) {
				t.Fatalf("Save after Full lost its inherited target = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
			assertContains(t, w.Body.String(), "Check the notices in the list", "Laptop", ip, "Outside the home network")
			reviewed := readDevicesForm(t, w.Body.String())
			if reviewed.Get("full") != mac || reviewed.Has("new") {
				t.Fatal("rejected Save lost the user's draft")
			}
			reviewed.Del("full")
			if w = setupRequest(h, "/devices", reviewed); w.Code != http.StatusSeeOther || f.applies != 1 || f.cfg.Clients[0].Mode != model.ModeOff {
				t.Fatalf("Save after reviewing the uncovered row = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
		})
	}
}

func TestDevicesAddressesNeededBeforeRoutingAndTargetLossFailsClosed(t *testing.T) {
	const mac = "02:00:00:00:00:25"
	for _, mode := range []model.Mode{model.ModeFull, model.ModeSplit} {
		t.Run(string(mode), func(t *testing.T) {
			f := newDevicesFixture(t)
			f.cfg.Clients = []model.Client{{MAC: mac, Mode: mode, Name: "Laptop"}}
			h := New(f, setupTestOptions(RoleManage))
			w := setupRequest(h, "/devices", nil)
			assertContains(t, w.Body.String(), "Waiting for a device address.")
			const ip = "203.0.113.25"
			f.discovered = []DiscoveredDevice{{MAC: mac, IP: ip}}
			page := setupRequest(h, "/devices", nil)
			assertContains(t, page.Body.String(), "Outside the home network")
			assertDeviceOutbound(t, f.Config(), mac, ip, "clients-full-block", model.TargetBlock)
		})
	}
}

func TestDevicesPreservesInheritedSplitWithOnlyANetworkDefault(t *testing.T) {
	const mac, ip = "02:00:00:00:00:25", "192.0.2.25"
	f := newDevicesFixture(t)
	f.cfg.Clients = nil
	f.cfg.ProviderRules.Off = true
	home := &f.cfg.Networks[0]
	home.Target, home.Default = "", "manual"
	f.discovered = []DiscoveredDevice{{MAC: mac, IP: ip, Name: "Laptop"}}
	h := New(f, setupTestOptions(RoleManage))
	form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	if !slices.Equal(form["split"], []string{mac}) {
		t.Fatalf("expected the inherited split switch on, got %v", form["split"])
	}
	form.Del("new")
	if w := setupRequest(h, "/devices", form); w.Code != http.StatusSeeOther || f.applies != 1 {
		t.Fatalf("Home Save with an untouched inherited split = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
	if home := f.cfg.Networks[0]; home.Mode != model.ModeOff || home.Default != "manual" || home.Target != "" ||
		!slices.Equal(f.cfg.Clients, []model.Client{{MAC: mac, Mode: model.ModeSplit}}) {
		t.Fatalf("Home = %+v, laptop = %+v", home, f.cfg.Clients)
	}
	assertDeviceOutbound(t, f.Config(), mac, ip, "clients-split-to-manual", "manual")
}

func assertDeviceOutbound(t *testing.T, cfg *model.Config, mac, ip, ruleSet, outbound string) {
	t.Helper()
	compiled, err := compile.Compile(compile.Input{
		Config: cfg, Neighbors: map[string]netip.Addr{mac: netip.MustParseAddr(ip)}, RuleSetDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var engine struct {
		Route struct {
			Rules []struct {
				RuleSet  []string `json:"rule_set"`
				Outbound string   `json:"outbound"`
				Action   string   `json:"action"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(compiled.SingBox, &engine); err != nil {
		t.Fatal(err)
	}
	for _, rule := range engine.Route.Rules {
		if slices.Equal(rule.RuleSet, []string{ruleSet}) && (rule.Outbound == outbound || outbound == model.TargetBlock && rule.Action == "reject") &&
			strings.Contains(string(compiled.RuleSets[ruleSet+".json"]), `"`+ip+`/32"`) {
			return
		}
	}
	t.Fatalf("saved laptop does not match %s for outbound %s", ruleSet, outbound)
}

func TestDevicesBulkStagesAllListedModesUntilSave(t *testing.T) {
	for _, mode := range []model.Mode{model.ModeSplit, model.ModeOff} {
		t.Run(string(mode), func(t *testing.T) {
			f := newDevicesFixture(t)
			h := New(f, setupTestOptions(RoleManage))
			before := f.Config()
			form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
			form.Set("bulk", string(mode))
			w := setupRequest(h, "/devices", form)
			if w.Code != http.StatusOK || f.applies != 0 || !reflect.DeepEqual(before, f.Config()) {
				t.Fatalf("bulk draft = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
			draft := readDevicesForm(t, w.Body.String())
			if draft.Get("new") != "1" || draft.Has("full") || strings.Count(w.Body.String(), "data-device-switch") != len(before.Clients) {
				t.Fatalf("bulk did not preserve the Home switch or replace full mode: %v", draft)
			}
			if w := setupRequest(h, "/devices", draft); w.Code != http.StatusSeeOther || f.applies != 1 {
				t.Fatalf("bulk Save = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
			for i := range before.Clients {
				before.Clients[i].Mode = mode
			}
			if !reflect.DeepEqual(before, f.Config()) {
				t.Fatalf("bulk %s saved clients %+v, want %+v", mode, f.cfg.Clients, before.Clients)
			}
		})
	}
}

func TestDevicesRejectsViewAndStaleWrites(t *testing.T) {
	f := newDevicesFixture(t)
	manage := New(f, setupTestOptions(RoleManage))
	form := readDevicesForm(t, setupRequest(manage, "/devices", nil).Body.String())
	form.Del("new")
	view := New(f, setupTestOptions(RoleView))
	w := setupRequest(view, "/devices", nil)
	body := w.Body.String()
	assertContains(t, body, "View only", `<fieldset class="devices-fields" disabled>`)
	if w.Code != http.StatusOK || readDevicesForm(t, body).Has("displayed") {
		t.Fatal("view-only page contains enabled device controls")
	}
	if w := setupRequest(view, "/devices", form); w.Code != http.StatusForbidden || f.applies != 0 {
		t.Errorf("forged view POST = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
	f.cfg.Groups[0].Entries = []string{"newer.example"}
	current := f.Config()
	w = setupRequest(manage, "/devices", form)
	if w.Code != http.StatusConflict || f.applies != 0 || !reflect.DeepEqual(current, f.Config()) {
		t.Fatalf("stale POST = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
	assertContains(t, w.Body.String(), "Settings changed in another window")
	if got := readDevicesForm(t, w.Body.String()); got.Get("rev") != Revision(current) || got.Get("new") != "1" {
		t.Fatalf("stale POST did not render current settings: %v", got)
	}
}

func TestDevicesRejectsInvalidSplitMode(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		prepare func(*model.Config)
		change  func(url.Values)
		want    []string
	}{
		{
			"targetless Home", func(cfg *model.Config) {
				cfg.Clients = nil
				cfg.Networks[0].Mode, cfg.Networks[0].Target, cfg.Networks[0].Default = model.ModeOff, "", ""
			}, func(form url.Values) { form.Set("new", "1") }, []string{`networks[0]`, "split mode needs a target"},
		},
		{
			"static address outside any network", func(cfg *model.Config) {
				cfg.Clients[1].IP, cfg.Clients[1].Target = "203.0.113.12", ""
			}, func(form url.Values) { form.Add("split", deviceTVMAC) }, []string{"Outside the home network"},
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newDevicesFixture(t)
			scenario.prepare(f.cfg)
			if err := f.cfg.Validate(); err != nil {
				t.Fatalf("test needs a valid starting configuration: %v", err)
			}
			before := f.Config()
			h := New(f, setupTestOptions(RoleManage))
			form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
			scenario.change(form)
			w := setupRequest(h, "/devices", form)
			if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(before, f.Config()) {
				t.Fatalf("invalid split = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
			assertContains(t, w.Body.String(), scenario.want...)
		})
	}
}

func TestDevicesRefusesSplitWithoutAnObservedNetworkTarget(t *testing.T) {
	const mac = "02:00:00:00:00:25"
	for _, tc := range []struct {
		name, seenIP, submittedIP string
		first                     *model.Network
		want                      string
	}{
		{"outside Home", "203.0.113.25", "203.0.113.25", nil, "Outside the home network"},
		{"moved after GET", "192.0.2.25", "203.0.113.25", nil, "Outside the home network"},
		{"in a guest network without a target", "198.51.100.25", "198.51.100.25",
			&model.Network{Name: "Isolated", CIDR: "198.51.100.0/24", Mode: model.ModeOff}, "Outside the home network"},
		{"first matching network has no target", "192.0.2.25", "192.0.2.25",
			&model.Network{Name: "Isolated", CIDR: "192.0.2.0/25", Mode: model.ModeOff}, "No VPN target for this device"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDevicesFixture(t)
			f.cfg.Clients = nil
			f.cfg.Networks[0].Mode = model.ModeOff
			if tc.first != nil {
				f.cfg.Networks = append([]model.Network{*tc.first}, f.cfg.Networks...)
			}
			f.discovered = []DiscoveredDevice{{MAC: mac, IP: tc.seenIP, Name: "Laptop"}}
			before := f.Config()
			h := New(f, setupTestOptions(RoleManage))
			page := setupRequest(h, "/devices", nil)
			form := readDevicesForm(t, page.Body.String())
			form.Set("split", mac)
			f.discovered[0].IP = tc.submittedIP
			w := setupRequest(h, "/devices", form)
			if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(before, f.Config()) {
				t.Fatalf("outside device Save = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
			assertContains(t, w.Body.String(), "Laptop", tc.want)
			if tc.seenIP == tc.submittedIP {
				assertContains(t, page.Body.String(), tc.want)
			}
		})
	}
}

func TestDevicesRejectsSplitPinAfterAddressMoves(t *testing.T) {
	const laptop, phone = "02:00:00:00:00:25", "02:00:00:00:00:26"
	for _, tc := range []struct {
		name, newIP  string
		guestDefault bool
	}{
		{"outside all networks", "203.0.113.25", false},
		{"guest has a default but no provider target", "198.51.100.25", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDevicesFixture(t)
			f.cfg.Clients = nil
			if tc.guestDefault {
				f.cfg.Networks[1].Target, f.cfg.Networks[1].Default = "", "manual"
			}
			f.discovered = []DiscoveredDevice{
				{MAC: laptop, IP: "192.0.2.25", Name: "Laptop"},
				{MAC: phone, IP: "192.0.2.26", Name: "Phone"},
			}
			before := f.Config()
			h := New(f, setupTestOptions(RoleManage))
			form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
			if !slices.Equal(form["split"], []string{laptop, phone}) {
				t.Fatalf("expected both devices to inherit split, got %v", form["split"])
			}
			form.Set("split", laptop) // Leave the laptop on, turn off the phone.
			form.Del("new")
			f.discovered[0].IP = tc.newIP
			w := setupRequest(h, "/devices", form)
			if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || !reflect.DeepEqual(before, f.Config()) {
				t.Fatalf("Save after the laptop moved = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
			assertContains(t, w.Body.String(), "Check the notices in the list", "Laptop", tc.newIP, "Outside the home network")
			reviewed := readDevicesForm(t, w.Body.String())
			if reviewed.Get("rev") != form.Get("rev") || reviewed.Has("new") || !slices.Equal(reviewed["split"], []string{laptop}) {
				t.Fatalf("rejected form did not retain the draft: %v", reviewed)
			}
			reviewed.Del("split")
			if w := setupRequest(h, "/devices", reviewed); w.Code != http.StatusSeeOther || f.applies != 1 {
				t.Fatalf("Save after switching the moved laptop off = HTTP %d, applies %d", w.Code, f.applies)
			}
			want := []model.Client{{MAC: laptop, Mode: model.ModeOff}, {MAC: phone, Mode: model.ModeOff}}
			if f.cfg.Networks[0].Mode != model.ModeOff || !slices.Equal(f.cfg.Clients, want) {
				t.Fatalf("reviewed Save stored Home %+v and clients %+v", f.cfg.Networks[0], f.cfg.Clients)
			}
		})
	}
}

func TestDevicesEnableAllSkipsOutsideHomeAndPinsItOff(t *testing.T) {
	const inside, outside = "02:00:00:00:00:25", "02:00:00:00:00:26"
	f := newDevicesFixture(t)
	f.cfg.Clients = nil
	f.cfg.Networks[0].Mode = model.ModeOff
	f.discovered = []DiscoveredDevice{
		{MAC: inside, IP: "192.0.2.25", Name: "Laptop"},
		{MAC: outside, IP: "203.0.113.26", Name: "Outside laptop"},
	}
	h := New(f, setupTestOptions(RoleManage))
	form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	form.Set("bulk", "split")
	w := setupRequest(h, "/devices", form)
	if w.Code != http.StatusOK || f.applies != 0 {
		t.Fatalf("Enable for all draft = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
	assertContains(t, w.Body.String(), "Skipped devices without a VPN target (1).")
	staged := readDevicesForm(t, w.Body.String())
	if !slices.Equal(staged["split"], []string{inside}) {
		t.Fatalf("Enable for all staged %v", staged["split"])
	}
	f.discovered = f.discovered[:1] // The skipped row may vanish before Save.
	if w := setupRequest(h, "/devices", staged); w.Code != http.StatusSeeOther || f.applies != 1 {
		t.Fatalf("bulk Save = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
	want := []model.Client{{MAC: inside, Mode: model.ModeSplit}, {MAC: outside, Mode: model.ModeOff}}
	if f.cfg.Networks[0].Mode != model.ModeOff || !slices.Equal(f.cfg.Clients, want) {
		t.Fatalf("bulk Save did not pin both displayed states: %+v", f.cfg.Clients)
	}
}

func TestDevicesCanEnableOutsideClientWithAnExistingTarget(t *testing.T) {
	f := newDevicesFixture(t)
	client := &f.cfg.Clients[1]
	client.IP = "203.0.113.25"
	want := *client
	want.Mode = model.ModeSplit
	h := New(f, setupTestOptions(RoleManage))
	form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	form.Add("split", deviceTVMAC)
	if w := setupRequest(h, "/devices", form); w.Code != http.StatusSeeOther || f.cfg.Clients[1] != want {
		t.Fatalf("existing manual target Save = HTTP %d and client %+v", w.Code, f.cfg.Clients[1])
	}
}

func TestDevicesHomeChangeKeepsSkippedDeviceOff(t *testing.T) {
	for _, tc := range []struct {
		name, firstIP string
		withTarget    bool
	}{
		{"skipped device moves into Home", "203.0.113.25", true},
		{"skipped device in a targetless Home", "192.0.2.25", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip := netip.MustParseAddr("192.0.2.25")
			f := newDevicesFixture(t)
			f.cfg.Clients = nil
			f.cfg.Networks[0].Mode = model.ModeOff
			if !tc.withTarget {
				f.cfg.ProviderRules.Off = true
				f.cfg.Networks[0].Target, f.cfg.Networks[0].Default = "", ""
			}
			f.discovered = []DiscoveredDevice{{MAC: deviceHomeMAC, IP: tc.firstIP, Name: "Laptop"}}
			h := New(f, setupTestOptions(RoleManage))
			form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
			form.Set("bulk", "split")
			staged := setupRequest(h, "/devices", form)
			if staged.Code != http.StatusOK {
				t.Fatalf("bulk draft = HTTP %d", staged.Code)
			}
			assertContains(t, staged.Body.String(), "Skipped devices without a VPN target (1).")
			form = readDevicesForm(t, staged.Body.String())
			form.Set("new", "1")
			f.discovered[0].IP = ip.String()
			if w := setupRequest(h, "/devices", form); w.Code != http.StatusSeeOther || f.applies != 1 {
				t.Fatalf("Home Save = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
			if f.cfg.Networks[0].Mode != model.ModeSplit || !slices.Equal(f.cfg.Clients, []model.Client{{MAC: deviceHomeMAC, Mode: model.ModeOff}}) {
				t.Errorf("Home = %+v, skipped client = %+v", f.cfg.Networks[0], f.cfg.Clients)
			}
			compiled, err := compile.Compile(compile.Input{
				Config: f.Config(), Neighbors: map[string]netip.Addr{deviceHomeMAC: ip}, RuleSetDir: t.TempDir(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if compiled.Split.Contains(ip) || !slices.Contains(compiled.Plan.Excluded, ip) {
				t.Fatal("the skipped device became a split client after the Home mode changed")
			}
		})
	}
}

func TestDevicesBulkDraftDoesNotMakeANewEnablePreviouslyOn(t *testing.T) {
	f := newDevicesFixture(t)
	f.cfg.Clients = nil
	f.cfg.Networks[0].Mode = model.ModeOff
	f.discovered = []DiscoveredDevice{{MAC: deviceHomeMAC, IP: "192.0.2.25", Name: "Laptop"}}
	h := New(f, setupTestOptions(RoleManage))
	form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	form.Set("bulk", "split")
	staged := setupRequest(h, "/devices", form)
	if staged.Code != http.StatusOK {
		t.Fatalf("bulk draft = HTTP %d", staged.Code)
	}
	form = readDevicesForm(t, staged.Body.String())
	if !slices.Equal(form["split"], []string{deviceHomeMAC}) {
		t.Fatalf("the eligible device did not stage a split mode: %v", form["split"])
	}
	f.discovered[0].IP = "203.0.113.25"
	if w := setupRequest(h, "/devices", form); w.Code != http.StatusUnprocessableEntity || f.applies != 0 {
		t.Fatalf("staged new enable outside Home = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
}

func TestDevicesRejectsATamperedDisplayedMode(t *testing.T) {
	f := newDevicesFixture(t)
	f.cfg.Clients = nil
	f.discovered = []DiscoveredDevice{{MAC: deviceHomeMAC, IP: "203.0.113.25", Name: "Laptop"}}
	h := New(f, setupTestOptions(RoleManage))
	form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	_, signature, _ := strings.Cut(form.Get("displayed"), ".")
	modified := base64.RawURLEncoding.EncodeToString([]byte(`{"` + deviceHomeMAC + `":"split"}`))
	form.Set("displayed", modified+"."+signature)
	form.Set("split", deviceHomeMAC)
	if w := setupRequest(h, "/devices", form); w.Code != http.StatusBadRequest || f.applies != 0 {
		t.Fatalf("tampered original mode = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
}

func TestDevicesEmptyStateCanSaveNewDevicePolicy(t *testing.T) {
	f := newDevicesFixture(t)
	f.cfg.Clients = nil
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/devices", nil)
	assertContains(t, page.Body.String(), "No LAN devices detected.")
	form := readDevicesForm(t, page.Body.String())
	form.Del("new")
	if w := setupRequest(h, "/devices", form); w.Code != http.StatusSeeOther || f.cfg.Networks[0].Mode != model.ModeOff || len(f.cfg.Clients) != 0 {
		t.Fatalf("empty page save = HTTP %d, Home mode %q, clients %d", w.Code, f.cfg.Networks[0].Mode, len(f.cfg.Clients))
	}
}

func TestDevicesMergeDiscoveryAndPinTheSubmittedSnapshot(t *testing.T) {
	const (
		cameraMAC = "02:00:00:00:00:05"
		noIPMAC   = "02:00:00:00:00:06"
		laterMAC  = "02:00:00:00:00:07"
	)
	f := newDevicesFixture(t)
	f.discovered = []DiscoveredDevice{
		{MAC: "02-00-00-00-00-01", IP: "192.0.2.99", Name: "Stale name"},
		{MAC: cameraMAC, IP: "192.0.2.15", Name: `Camera<script>`},
		{MAC: noIPMAC},
	}
	h := New(f, setupTestOptions(RoleManage))
	w := setupRequest(h, "/devices", nil)
	assertContains(t, w.Body.String(), "Camera&lt;script&gt;", "192.0.2.15", "MAC "+noIPMAC)
	if strings.Contains(w.Body.String(), "Stale name") || strings.Contains(w.Body.String(), "192.0.2.99") {
		t.Fatal("discovery replaced a manual name or static address")
	}
	form := readDevicesForm(t, w.Body.String())
	if strings.Count(w.Body.String(), "data-device-switch") != 6 || !slices.Contains(form["split"], cameraMAC) || !slices.Contains(form["split"], noIPMAC) {
		t.Fatalf("discovered devices did not appear once with their inherited states: %v", form)
	}
	form.Del("new")
	f.discovered = []DiscoveredDevice{{MAC: laterMAC, IP: "192.0.2.16", Name: "Later arrival"}}
	if w := setupRequest(h, "/devices", form); w.Code != http.StatusSeeOther {
		t.Fatalf("Save while discovery changes = HTTP %d", w.Code)
	}
	added := f.cfg.Clients[4:]
	want := []model.Client{{MAC: cameraMAC, Mode: model.ModeSplit}, {MAC: noIPMAC, Mode: model.ModeSplit}}
	if !slices.Equal(added, want) || f.cfg.Networks[0].Mode != model.ModeOff {
		t.Fatalf("Save pinned the wrong clients or copied observations: %+v", added)
	}
	latest := setupRequest(h, "/devices", nil).Body.String()
	reloaded := readDevicesForm(t, latest)
	if strings.Count(latest, "data-device-switch") != 7 || !strings.Contains(latest, "Later arrival") || slices.Contains(reloaded["split"], laterMAC) {
		t.Fatalf("new device did not inherit the new policy: %v", reloaded)
	}
}

func TestDevicesRejectsForgedFullMode(t *testing.T) {
	f := newDevicesFixture(t)
	h := New(f, setupTestOptions(RoleManage))
	form := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	form.Add("full", deviceTVMAC)
	if w := setupRequest(h, "/devices", form); w.Code != http.StatusBadRequest || f.applies != 0 {
		t.Fatalf("forged full-mode POST = HTTP %d, Apply calls %d", w.Code, f.applies)
	}
}

type devicesFixture struct {
	Deps
	cfg        *model.Config
	discovered []DiscoveredDevice
	applies    int
}

func newDevicesFixture(t *testing.T) *devicesFixture {
	t.Helper()
	cfg := &model.Config{
		Subscriptions: []subscription.Source{{ID: "sample", URL: "https://provider.example/catalog"}},
		Connections:   []model.Connection{{ID: "manual", Type: model.ConnLink, Link: "socks5://reserve.example:1080"}},
		Clients: []model.Client{
			{MAC: deviceFullMAC, IP: "192.0.2.11", Name: "Office <script>", Mode: model.ModeFull, Target: "manual"},
			{MAC: deviceTVMAC, IP: "192.0.2.12", Name: "TV", Mode: model.ModeOff, Target: "manual"},
			{MAC: deviceHomeMAC},
			{MAC: deviceGuestMAC, IP: "198.51.100.14", Name: "Guest laptop"},
		},
		Groups: []model.Group{{Name: "own-direct", Target: model.TargetDirect, Entries: []string{"saved.example"}}},
	}
	cfg.RouteHomeThroughSubscription("sample", netip.MustParsePrefix("192.0.2.0/24"))
	cfg.Networks = append(cfg.Networks, model.Network{Name: "Guest", CIDR: "198.51.100.0/24", Mode: model.ModeOff, Target: "manual"})
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return &devicesFixture{cfg: cfg}
}

func (f *devicesFixture) Config() *model.Config { return f.cfg.Clone() }

func (f *devicesFixture) Devices() []DiscoveredDevice { return f.discovered }

func (f *devicesFixture) Apply(_ context.Context, cfg *model.Config, rev string) error {
	f.applies++
	if Revision(f.Config()) != rev {
		return model.ErrConfigChanged
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	f.cfg = cfg.Clone()
	return nil
}

// readDevicesForm takes the values a native Save submits, including only
// checked checkboxes and controls outside a disabled fieldset.
func readDevicesForm(t *testing.T, body string) url.Values {
	t.Helper()
	tokens := html.NewTokenizer(strings.NewReader(body))
	form := url.Values{}
	inForm, disabled := false, false
	for kind := tokens.Next(); kind != html.ErrorToken; kind = tokens.Next() {
		tag := tokens.Token()
		if inForm && kind == html.EndTagToken && tag.Data == "form" {
			return form
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		attrs := map[string]string{}
		for _, attr := range tag.Attr {
			attrs[attr.Key] = attr.Val
		}
		switch tag.Data {
		case "form":
			inForm = attrs["action"] == "/devices"
		case "fieldset":
			if inForm {
				_, disabled = attrs["disabled"]
			}
		case "input":
			_, checked := attrs["checked"]
			_, inputDisabled := attrs["disabled"]
			if inForm && !disabled && !inputDisabled && attrs["name"] != "" && (attrs["type"] != "checkbox" || checked) {
				form.Add(attrs["name"], attrs["value"])
			}
		}
	}
	if tokens.Err() != io.EOF {
		t.Fatal(tokens.Err())
	}
	t.Fatal("no devices form in response")
	return nil
}
