package ui

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/html"

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
	if len(form["device"]) != 4 || !slices.Equal(form["split"], []string{deviceHomeMAC}) ||
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
			if draft.Get("new") != "1" || draft.Has("full") || len(draft["device"]) != len(before.Clients) {
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
	if w.Code != http.StatusOK || readDevicesForm(t, body).Has("device") {
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
		label   string
	}{
		{
			"targetless Home", func(cfg *model.Config) {
				cfg.Clients = nil
				cfg.Networks[0].Mode, cfg.Networks[0].Target, cfg.Networks[0].Default = model.ModeOff, "", ""
			}, func(form url.Values) { form.Set("new", "1") }, `networks[0]`,
		},
		{
			"static address outside any network", func(cfg *model.Config) {
				cfg.Clients[1].IP, cfg.Clients[1].Target = "203.0.113.12", ""
			}, func(form url.Values) { form.Add("split", deviceTVMAC) }, `clients[1]`,
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
			assertContains(t, w.Body.String(), scenario.label, "split mode needs a target")
		})
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
	if len(form["device"]) != 6 || !slices.Contains(form["split"], cameraMAC) || !slices.Contains(form["split"], noIPMAC) {
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
	reloaded := readDevicesForm(t, setupRequest(h, "/devices", nil).Body.String())
	if len(reloaded["device"]) != 7 || !slices.Contains(reloaded["device"], laterMAC) || slices.Contains(reloaded["split"], laterMAC) {
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
			if inForm && !disabled && attrs["name"] != "" && (attrs["type"] != "checkbox" || checked) {
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
