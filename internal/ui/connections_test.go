package ui

import (
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	subscriptionCheckPath = "/connections/subscriptions/sample/check"
	subscriptionNodesPath = "/fragments/connections/sample"
)

func TestConnectionsDisplaysAppliedState(t *testing.T) {
	f := newConnectionsFixture(t)
	f.subs[0].Metadata.Title = `Example <script>`
	f.subs[0].Nodes[0].Name = `North "</button><script>"`
	h := New(f, setupTestOptions(RoleManage))
	w := setupRequest(h, "/connections", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /connections = HTTP %d", w.Code)
	}
	assertPageHeaders(t, w.Result(), "en")
	body := w.Body.String()
	assertContains(t, body, `href="/connections" aria-current="page"`, `data-fragment="`+subscriptionNodesPath+`"`,
		"Example &lt;script&gt;", "North &#34;&lt;/button&gt;&lt;script&gt;&#34;", "Ready", "Active", "42 ms", "Last updated",
		`href="/connections/new"`, `href="/connections/old"`, "VLESS", "No response", "Cabin → Direct", "35 ms", "Office SOCKS", "Disabled")
	if strings.Contains(body, "<script>") || strings.Contains(body, "synthetic-token") || strings.Contains(body, "style=") {
		t.Fatal("the page exposed a secret, raw provider markup, or an inline style")
	}
	for _, id := range []string{"old", "backup", "disabled"} {
		input := connectionControl(t, body, "input", "enabled."+id, "1")
		if _, checked := input["checked"]; checked == (id == "disabled") {
			t.Errorf("connection %q checked = %v", id, checked)
		}
	}
	options := connectionOptionsFromPage(t, body, "fallback.sample")
	if want := []string{"old", "backup", "disabled", model.TargetDirect, model.TargetBlock}; !slices.Equal(options, want) {
		t.Fatalf("reserve options = %v, want %v", options, want)
	}
	for _, target := range options {
		candidate := f.Config()
		candidate.Subscriptions[0].Fallback = target
		if err := candidate.Validate(); err != nil {
			t.Errorf("the select offered a reserve rejected by the model: %q: %v", target, err)
		}
	}
}

func TestConnectionsSaveChangesOnlyReservesAndSwitches(t *testing.T) {
	f := newConnectionsFixture(t)
	f.cfg.Paused = true
	f.cfg.Subscriptions = append(f.cfg.Subscriptions, subscription.Source{ID: "extra", URL: "https://second.example/config"})
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/connections", nil).Body.String()
	if options := connectionOptionsFromPage(t, page, "fallback.extra"); !slices.Contains(options, model.TargetBlock) {
		t.Fatal("the second configured subscription has no reserve select")
	}
	want := f.Config()
	want.Subscriptions[0].Fallback = "disabled"
	want.Subscriptions[1].Fallback = model.TargetBlock
	want.Connections[0].Disabled = true
	want.Connections[2].Disabled = false
	form := connectionsSaveForm(t, page)
	form.Set("fallback.sample", "disabled")
	form.Set("fallback.extra", model.TargetBlock)
	form.Set("enabled.old", "0")
	form.Add("enabled.disabled", "1")
	w := setupRequest(h, "/connections", form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/connections" || f.applies != 1 {
		t.Fatalf("save = HTTP %d, location %q, Apply calls %d", w.Code, w.Header().Get("Location"), f.applies)
	}
	if !reflect.DeepEqual(f.Config(), want) {
		t.Fatal("save lost unrelated settings or did not persist the staged edits")
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("save did not carry a flash to the redirected page")
	}
}

func TestConnectionsPreservesAnUnsetReserveUntilExplicitlyChanged(t *testing.T) {
	f := newConnectionsFixture(t)
	f.cfg.Subscriptions[0].Fallback = ""
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/connections", nil).Body.String()
	if options := connectionOptionsFromPage(t, page, "fallback.sample"); !slices.Contains(options, "") || !slices.Contains(options, model.TargetBlock) {
		t.Fatalf("saved unset reserve and explicit block must be distinct in the select: %v", options)
	}
	form := connectionsSaveForm(t, page)
	form.Set("fallback.sample", "")
	form.Set("enabled.old", "0")
	if w := setupRequest(h, "/connections", form); w.Code != http.StatusSeeOther || f.cfg.Subscriptions[0].Fallback != "" || !f.cfg.Connections[0].Disabled {
		t.Fatalf("saving an unrelated switch with an unset reserve returned HTTP %d or changed the reserve", w.Code)
	}
}

func TestConnectionsRejectsInvalidAndStaleSaves(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		err    error
		status int
		text   string
	}{
		{"pinned node", model.ManagedTarget("sample", overviewNodeID), nil, http.StatusUnprocessableEntity, "Choose a valid reserve"},
		{"automatic selection", model.ManagedTarget("sample", "auto"), nil, http.StatusUnprocessableEntity, "Choose a valid reserve"},
		{"unknown connection", "missing", nil, http.StatusUnprocessableEntity, "Choose a valid reserve"},
		{"stale form", "", nil, http.StatusConflict, "Settings changed in another window"},
		{"concurrent Apply", model.TargetDirect, model.ErrConfigChanged, http.StatusConflict, "Settings changed in another window"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConnectionsFixture(t)
			h := New(f, setupTestOptions(RoleManage))
			form := connectionsSaveForm(t, setupRequest(h, "/connections", nil).Body.String())
			if tc.target == "" {
				f.cfg.Paused = true
			} else {
				form.Set("fallback.sample", tc.target)
			}
			before := f.Config()
			f.saveErr = tc.err
			w := setupRequest(h, "/connections", form)
			if w.Code != tc.status || f.applies != 0 || !reflect.DeepEqual(f.Config(), before) {
				t.Fatalf("save = HTTP %d, Apply calls %d", w.Code, f.applies)
			}
			assertContains(t, w.Body.String(), tc.text)
		})
	}
}

func TestConnectionsChecksNodesAndRefreshesStatusFragment(t *testing.T) {
	f := newConnectionsFixture(t)
	h := New(f, setupTestOptions(RoleManage))
	page := setupRequest(h, "/connections", nil).Body.String()
	assertContains(t, page, `action="`+subscriptionCheckPath+`"`, "Check all nodes")
	rev := formField(t, page, "rev")
	before := f.Config()
	for _, node := range []string{overviewNodeID, ""} {
		w := setupRequest(h, subscriptionCheckPath, url.Values{"rev": {rev}, "node": {node}})
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/connections" || len(w.Result().Cookies()) == 0 {
			t.Fatalf("probe %q = HTTP %d, location %q", node, w.Code, w.Header().Get("Location"))
		}
	}
	if !slices.Equal(f.nodeChecks, [][2]string{{"sample", overviewNodeID}, {"sample", ""}}) || f.applies != 0 || !reflect.DeepEqual(f.Config(), before) {
		t.Fatalf("node checks = %v, Apply calls %d", f.nodeChecks, f.applies)
	}
	fragment := setupRequest(h, subscriptionNodesPath, nil)
	if fragment.Code != http.StatusOK {
		t.Fatalf("fragment returned HTTP %d", fragment.Code)
	}
	assertPageHeaders(t, fragment.Result(), "en")
	assertContains(t, fragment.Body.String(), "42 ms")
	newLatency := int64(73)
	f.subs[0].Nodes[0].LatencyMS = &newLatency
	updated := setupRequest(h, subscriptionNodesPath, nil).Body.String()
	assertContains(t, updated, "73 ms")
	if strings.Contains(updated, "<!doctype") || strings.Contains(updated, "fallback.sample") {
		t.Fatal("the live fragment included page layout or editable reserve fields")
	}
	w := setupRequest(h, subscriptionCheckPath, url.Values{"rev": {rev}})
	if w.Code != http.StatusBadRequest || len(f.nodeChecks) != 2 {
		t.Fatalf("an omitted node control must not queue an all-node check: HTTP %d", w.Code)
	}
	f.cfg.Subscriptions[0].URL = "https://provider.example/replaced"
	w = setupRequest(h, subscriptionCheckPath, url.Values{"rev": {rev}, "node": {""}})
	if w.Code != http.StatusConflict || len(f.nodeChecks) != 2 {
		t.Fatalf("stale probe = HTTP %d, calls %v", w.Code, f.nodeChecks)
	}
	assertContains(t, w.Body.String(), "Settings changed in another window")
}

func TestConnectionsViewRoleCannotSaveOrCheck(t *testing.T) {
	f := newConnectionsFixture(t)
	h := New(f, setupTestOptions(RoleView))
	page := setupRequest(h, "/connections", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("view-only page returned HTTP %d", page.Code)
	}
	body := page.Body.String()
	assertContains(t, body, "View only", `href="/connections/backup"`)
	for _, control := range []struct{ tag, name, value string }{
		{"select", "fallback.sample", ""}, {"input", "enabled.old", "1"}, {"button", "node", overviewNodeID}, {"button", "node", ""},
	} {
		attrs := connectionControl(t, body, control.tag, control.name, control.value)
		if _, disabled := attrs["disabled"]; !disabled {
			t.Errorf("%s %q was enabled for the view role", control.tag, control.name)
		}
	}
	if strings.Contains(body, `href="/connections/new"`) {
		t.Error("the view role received an active add connection link")
	}
	form := connectionsSaveForm(t, body)
	for _, path := range []string{"/connections", subscriptionCheckPath} {
		w := setupRequest(h, path, form)
		if w.Code != http.StatusForbidden || f.applies != 0 || len(f.nodeChecks) != 0 {
			t.Fatalf("forged POST %s = HTTP %d, Apply calls %d, checks %v", path, w.Code, f.applies, f.nodeChecks)
		}
	}
	viewerFragment := setupRequest(h, subscriptionNodesPath, nil)
	button := connectionControl(t, viewerFragment.Body.String(), "button", "node", overviewNodeID)
	if _, disabled := button["disabled"]; !disabled {
		t.Fatal("view role's fragment re-enabled the check button")
	}
	denied := setupRequest(New(f, setupTestOptions(RoleDeny)), subscriptionNodesPath, nil)
	if denied.Code != http.StatusForbidden || strings.Contains(denied.Body.String(), "North") {
		t.Fatalf("fragment returned status %d or exposed a node to a denied role", denied.Code)
	}
}

func TestConnectionsEmptyAndExpired(t *testing.T) {
	f := newConnectionsFixture(t)
	h := New(f, setupTestOptions(RoleManage))
	f.cfg.Connections = nil
	f.subs[0].Metadata.Usage.Expire = time.Now().Add(-time.Hour).Unix()
	f.subs[0].Nodes = nil
	f.subs[0].Unavailable = true
	w := setupRequest(h, "/connections", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expired page returned HTTP %d", w.Code)
	}
	assertContains(t, w.Body.String(), "Expired", "No nodes", "No manual connections")
	f.cfg.Subscriptions = nil
	w = setupRequest(h, "/connections", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("empty page returned HTTP %d", w.Code)
	}
	assertContains(t, w.Body.String(), "No subscription configured", "No manual connections")
}

type connectionsFixture struct {
	*overviewFixture
	nodeChecks [][2]string
}

func newConnectionsFixture(t *testing.T) *connectionsFixture {
	t.Helper()
	f := &connectionsFixture{overviewFixture: newOverviewFixture()}
	f.cfg.Subscriptions[0].Fallback = "backup"
	f.cfg.Connections[0].Link = "vless://11111111-2222-3333-4444-555555555555@example.test:443?encryption=none"
	f.cfg.Connections[0].Fallback = "backup"
	f.cfg.Connections[1].Fallback = model.TargetDirect
	f.cfg.Connections[1].WireGuard = &model.WireGuard{
		PrivateKey: "synthetic-token", Address: []string{"198.51.100.2/32"},
		Peer: model.WGPeer{Endpoint: "example.test:51820", PublicKey: "synthetic-key"},
	}
	f.cfg.Connections[2].Link = "socks5://example.test:1080"
	f.cfg.Defaults()
	if err := f.cfg.Validate(); err != nil {
		t.Fatalf("invalid connections fixture: %v", err)
	}
	return f
}

func (f *connectionsFixture) CheckSubscription(source, node, revision string) error {
	if Revision(f.Config()) != revision {
		return model.ErrConfigChanged
	}
	for i := range f.subs {
		sub := &f.subs[i]
		if sub.ID != source || len(sub.Nodes) == 0 {
			continue
		}
		for j := range sub.Nodes {
			if node == "" || node == sub.Nodes[j].ID {
				f.nodeChecks = append(f.nodeChecks, [2]string{source, node})
				return nil
			}
		}
	}
	return errors.New("saved node missing")
}

func connectionsSaveForm(t *testing.T, body string) url.Values {
	t.Helper()
	return url.Values{
		"rev": {formField(t, body, "rev")}, "fallback.sample": {"backup"},
		"enabled.old": {"0", "1"}, "enabled.backup": {"0", "1"}, "enabled.disabled": {"0"},
	}
}

func connectionControl(t *testing.T, body, element, name, value string) map[string]string {
	t.Helper()
	tokens := html.NewTokenizer(strings.NewReader(body))
	for kind := tokens.Next(); kind != html.ErrorToken; kind = tokens.Next() {
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		tag := tokens.Token()
		attrs := connectionAttrs(tag)
		if tag.Data == element && attrs["name"] == name && attrs["value"] == value {
			return attrs
		}
	}
	t.Fatalf("missing %s %q=%q", element, name, value)
	return nil
}

func connectionOptionsFromPage(t *testing.T, body, name string) []string {
	t.Helper()
	tokens := html.NewTokenizer(strings.NewReader(body))
	var options []string
	inside := false
	for kind := tokens.Next(); kind != html.ErrorToken; kind = tokens.Next() {
		tag := tokens.Token()
		switch {
		case kind == html.StartTagToken && tag.Data == "select":
			inside = connectionAttrs(tag)["name"] == name
		case inside && kind == html.StartTagToken && tag.Data == "option":
			options = append(options, connectionAttrs(tag)["value"])
		case inside && kind == html.EndTagToken && tag.Data == "select":
			return options
		}
	}
	t.Fatalf("missing reserve select %s", name)
	return nil
}

func connectionAttrs(tag html.Token) map[string]string {
	attrs := make(map[string]string, len(tag.Attr))
	for _, attr := range tag.Attr {
		attrs[attr.Key] = attr.Val
	}
	return attrs
}
