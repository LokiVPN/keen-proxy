package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/connectionimport"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const wizardUUID = "00000000-0000-4000-8000-000000000000"
const wizardLink = "vless://" + wizardUUID + "@vpn.example.test:443?security=tls&sni=cover.example.test"
const wizardWGKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
const wizardConf = "[Interface]\nPrivateKey=" + wizardWGKey + "\nAddress=10.1.0.2/32\n" +
	"[Peer]\nPublicKey=" + wizardWGKey + "\nEndpoint=vpn.example.test:51820\n"

type wizardFixture struct {
	*setupFixture
	validations int
	validateErr error
	runtimeTags []string
}

func (f *wizardFixture) ConnectionRuntimeTags(*model.Config) ([]string, error) {
	return f.runtimeTags, nil
}

func newWizardFixture() *wizardFixture {
	cfg := &model.Config{}
	cfg.Defaults()
	return &wizardFixture{setupFixture: &setupFixture{cfg: cfg}}
}

func (f *wizardFixture) ValidateConnection(_ context.Context, cfg *model.Config, id string) error {
	f.validations++
	for _, c := range cfg.Connections {
		if c.ID == id {
			return errors.Join(cfg.Validate(), f.validateErr)
		}
	}
	return errors.New("candidate did not contain the connection")
}

func wizardPost(h http.Handler, target string, values url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func wizardCheck(t *testing.T, h http.Handler, entry, payload string) (*httptest.ResponseRecorder, url.Values) {
	t.Helper()
	start := setupRequest(h, entry, nil)
	if start.Code != http.StatusOK {
		t.Fatalf("wizard GET %s returned %d", entry, start.Code)
	}
	rev := formField(t, start.Body.String(), "rev")
	form := url.Values{"rev": {rev}, "method": {"paste"}, "profile": {payload}}
	if entry != "/connections/new" {
		form.Set("replace", formField(t, start.Body.String(), "replace"))
	}
	checked := wizardPost(h, "/connections/new/check", form)
	if checked.Code != http.StatusOK {
		t.Fatalf("check returned HTTP %d: %s", checked.Code, checked.Body.String())
	}
	return checked, url.Values{"rev": {rev}, "preview": {formField(t, checked.Body.String(), "preview")}, "name": {"Work"}}
}

func TestConnectionWizardCheckSaveAndFlash(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	w, save := wizardCheck(t, h, "/connections/new", wizardLink+"#Work%20%3Cscript%3E")
	for _, want := range []string{"VLESS", "vpn.example.test:443", "cover.example.test", "VLESS 1", `name="id" value="vless"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("checked page lacks %q", want)
		}
	}
	if strings.Contains(w.Body.String(), wizardUUID) || strings.Contains(w.Body.String(), "Work &lt;script&gt;") || f.applies != 0 {
		t.Fatal("check disclosed or applied the draft")
	}
	save.Set("id", "work")
	save.Set("profile", "ignored-secret")
	saved := wizardPost(h, "/connections/new/save", save, w.Result().Cookies()...)
	if saved.Code != http.StatusSeeOther || saved.Header().Get("Location") != "/connections" {
		t.Fatalf("save did not redirect to Connections: %d", saved.Code)
	}
	if f.applies != 1 || f.validations < 1 || len(f.cfg.Connections) != 1 || f.cfg.Connections[0].Link != wizardLink+"#Work%20%3Cscript%3E" {
		t.Fatal("Apply did not receive the checked profile")
	}
	follow := httptest.NewRequest(http.MethodGet, "/connections", nil)
	for _, c := range saved.Result().Cookies() {
		follow.AddCookie(c)
	}
	page := httptest.NewRecorder()
	h.ServeHTTP(page, follow)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), translations["en"]["flash_saved"]) {
		t.Fatal("Connections did not display the save flash")
	}
	// Even replacement with an unchanged revision may use a draft only once.
	save.Set("rev", Revision(f.cfg))
	replayed := wizardPost(h, "/connections/new/save", save, w.Result().Cookies()...)
	if replayed.Code != http.StatusConflict || f.applies != 1 {
		t.Fatal("a consumed token applied again")
	}
}

func TestConnectionWizardSuggestsProtocolIdentityForImports(t *testing.T) {
	const password = "fixture-private-password"
	const label = "fixture-imported-label"
	const header = "fixture-header-value"
	for _, tt := range []struct{ name, profile, wantName, wantID, hidden string }{
		{"share link", wizardLink + "#Work-" + label + "-" + wizardUUID, "VLESS 1", "vless", wizardUUID},
		{"port hopping", "hy2://q@vpn.example.test:443,8443?up=073#server073", "Hysteria2 1", "hysteria2", "server073"},
		{"semicolon query", "trojan://q@vpn.example.test:443?token=" + password + ";other=1#Office-" + password,
			"Trojan 1", "trojan", password},
		{"JSON tag", `{"type":"trojan","server":"vpn.example.test","server_port":443,"password":"q","tag":"office-q","tls":{"enabled":true}}`,
			"Trojan 1", "trojan", "office-q"},
		{"HTTP header", `{"type":"http","server":"vpn.example.test","server_port":8080,"headers":{"Proxy-Authorization":"Basic ` + header +
			`"},"tag":"Office ` + header + `"}`, "HTTP 1", "http", header},
		{"ShadowTLS tag", `{"type":"shadowtls","server":"vpn.example.test","server_port":443,"tag":"fixture-imported-label"}`,
			"ShadowTLS 1", "shadowtls", label},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newWizardFixture()
			opts := setupTestOptions(RoleManage)
			role := RoleManage
			opts.Role = func(*http.Request) Role { return role }
			h := New(f, opts)
			checked, save := wizardCheck(t, h, "/connections/new", tt.profile)
			body := checked.Body.String()
			save.Set("name", html.UnescapeString(formField(t, body, "name")))
			save.Set("id", formField(t, body, "id"))
			if save.Get("name") != tt.wantName || save.Get("id") != tt.wantID ||
				strings.Contains(body, tt.hidden) || strings.Contains(body, label) || !strings.Contains(body, "vpn.example.test") {
				t.Error("Check did not show the generic protocol identity and server")
			}
			if saved := wizardPost(h, "/connections/new/save", save, checked.Result().Cookies()...); saved.Code != http.StatusSeeOther {
				t.Fatalf("default save returned HTTP %d", saved.Code)
			}
			role = RoleView
			page := setupRequest(h, "/connections", nil)
			got := f.cfg.Connections[0]
			if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), tt.wantName) || strings.Contains(page.Body.String(), tt.hidden) ||
				got.Name != tt.wantName || got.ID != tt.wantID {
				t.Fatal("the saved default did not preserve the generic identity for viewers")
			}
		})
	}
}

func TestConnectionWizardSkipsConfiguredAndGeneratedIDs(t *testing.T) {
	f := newWizardFixture()
	f.cfg.Connections = []model.Connection{{ID: "trojan", Type: model.ConnLink, Link: "socks5://old.example:1080"}}
	f.runtimeTags = []string{"trojan-2"}
	h := New(f, setupTestOptions(RoleManage))
	checked, _ := wizardCheck(t, h, "/connections/new", "trojan://fixture-private@vpn.example.test:443#Office")
	body := checked.Body.String()
	if formField(t, body, "name") != "Trojan 3" || formField(t, body, "id") != "trojan-3" {
		t.Fatal("Check did not skip the configured ID and generated tag")
	}
}

func TestConnectionWizardAcceptsOperatorIdentity(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	checked, save := wizardCheck(t, h, "/connections/new",
		`{"type":"trojan","server":"vpn.example.test","server_port":443,"password":"fixture-private","tls":{"enabled":true}}`)
	save.Set("id", "trojan-office")
	save.Set("name", "My Trojan connection")
	if saved := wizardPost(h, "/connections/new/save", save, checked.Result().Cookies()...); saved.Code != http.StatusSeeOther {
		t.Fatalf("Save rejected an otherwise valid operator choice, HTTP %d", saved.Code)
	}
	if got := f.cfg.Connections[0]; got.ID != "trojan-office" || got.Name != "My Trojan connection" {
		t.Fatal("Save changed the operator's chosen identity")
	}
}

func TestConnectionWizardSavesBothWireGuardAddressFamilies(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	conf := strings.Replace(wizardConf, "[Peer]", "Address=2001:db8::2/128\nDNS=1.1.1.1\nDNS=8.8.8.8\n[Peer]", 1)
	conf += "AllowedIPs=0.0.0.0/0\nAllowedIPs=::/0\n"
	checked, save := wizardCheck(t, h, "/connections/new", conf)
	save.Set("id", "dual-stack")
	if w := wizardPost(h, "/connections/new/save", save, checked.Result().Cookies()...); w.Code != http.StatusSeeOther {
		t.Fatalf("could not save the WireGuard profile: HTTP %d", w.Code)
	}
	wg := f.cfg.Connections[0].WireGuard
	if !slices.Equal(wg.Address, []string{"10.1.0.2/32", "2001:db8::2/128"}) ||
		!slices.Equal(wg.Peer.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
		t.Fatal("save did not retain both WireGuard address families")
	}
}

func TestConnectionWizardReplaceLegacyIDs(t *testing.T) {
	for _, id := range []string{"new", ".", "..", "~home", "path/with\nline"} {
		t.Run(id, func(t *testing.T) {
			f := newWizardFixture()
			f.cfg.Paused = true
			f.cfg.Connections = []model.Connection{
				{ID: id, Name: "Home", Type: model.ConnLink, Link: "socks5://old.example:1080", Disabled: true, Fallback: "backup"},
				{ID: "backup", Type: model.ConnLink, Link: "socks5://backup.example:1080"},
				{ID: "another", Type: model.ConnLink, Link: "socks5://other.example:1080", Fallback: id},
			}
			f.cfg.Networks = []model.Network{{Name: "Home", CIDR: "192.0.2.0/24", Mode: model.ModeSplit, Target: id, Default: id}}
			f.cfg.Groups = []model.Group{{Name: "own-vpn", Target: id, Entries: []string{"example.test"}}}
			f.cfg.Subscriptions = []subscription.Source{{ID: "main", URL: "https://provider.example/source", Fallback: id}}
			want := f.cfg.Clone()
			want.Connections[0].Link = wizardLink
			h := New(f, setupTestOptions(RoleManage))
			w, form := wizardCheck(t, h, connectionDetailPath(id)+"/replace", wizardLink)
			form.Set("id", "forged-id")
			form.Set("replace", connectionIDSegment("backup"))
			form.Set("name", "Home")
			saved := wizardPost(h, "/connections/new/save", form, w.Result().Cookies()...)
			if saved.Code != http.StatusSeeOther || f.applies != 1 || !reflect.DeepEqual(f.cfg, want) {
				t.Fatalf("replace of %q did not preserve its config and references (HTTP %d)", id, saved.Code)
			}
		})
	}
}

func TestConnectionWizardSessionAndRevision(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	w, form := wizardCheck(t, h, "/connections/new", wizardLink)
	form.Set("id", "work")
	other, _ := wizardCheck(t, h, "/connections/new", wizardLink)
	if got := wizardPost(h, "/connections/new/save", form, other.Result().Cookies()...); got.Code != http.StatusConflict || f.applies != 0 {
		t.Fatal("another session could use the checked draft")
	}
	f.cfg.Paused = true
	stale := wizardPost(h, "/connections/new/save", form, w.Result().Cookies()...)
	if stale.Code != http.StatusConflict || !strings.Contains(stale.Body.String(), translations["en"]["revision_changed"]) || f.applies != 0 {
		t.Fatal("stale draft applied")
	}
	badCheck := wizardPost(h, "/connections/new/check", url.Values{"rev": {form.Get("rev")}, "method": {"paste"}, "profile": {wizardLink}})
	if badCheck.Code != http.StatusConflict || !strings.Contains(badCheck.Body.String(), translations["en"]["revision_changed"]) {
		t.Fatal("stale check was accepted")
	}
}

func TestConnectionWizardUsesVerifiedSessionKey(t *testing.T) {
	f := newWizardFixture()
	opts := setupTestOptions(RoleManage)
	opts.SessionKey = func(r *http.Request) [32]byte {
		c, err := r.Cookie("test-router-session")
		if err != nil {
			return [32]byte{}
		}
		return sha256.Sum256([]byte(c.Value))
	}
	h := New(f, opts)
	original := &http.Cookie{Name: "test-router-session", Value: "synthetic-session-one"}
	newSession := &http.Cookie{Name: original.Name, Value: "synthetic-session-two"}
	form := url.Values{"rev": {Revision(f.Config())}, "method": {"paste"}, "profile": {wizardLink}}
	checked := wizardPost(h, "/connections/new/check", form, original)
	if checked.Code != http.StatusOK || len(checked.Result().Cookies()) != 0 {
		t.Fatal("managed router session did not receive a checked draft")
	}
	form.Set("preview", formField(t, checked.Body.String(), "preview"))
	form.Set("name", "Work")
	form.Set("id", "work")
	if got := wizardPost(h, "/connections/new/save", form, newSession); got.Code != http.StatusConflict || f.applies != 0 {
		t.Fatal("a fresh session for the same user could use an old session's draft")
	}
	if got := wizardPost(h, "/connections/new/save", form, original); got.Code != http.StatusSeeOther || f.applies != 1 {
		t.Fatal("the original session could not save its draft")
	}
}

func TestConnectionWizardDraftExpiryAndSingleUse(t *testing.T) {
	var drafts connectionDrafts
	start := time.Unix(120, 0)
	draft := connectionDraft{
		rev: "revision", session: sha256.Sum256([]byte("synthetic-session")),
		expires: start.Add(connectionDraftLifetime), candidates: []connectionimport.Draft{{}},
	}
	token := drafts.put(draft, start)
	if _, ok := drafts.take(token, draft.rev, draft.session, false, draft.expires); ok {
		t.Fatal("draft was accepted after expiry")
	}
	token = drafts.put(draft, start)
	taken := make(chan bool, 2)
	for range 2 {
		go func() {
			_, ok := drafts.take(token, draft.rev, draft.session, false, start)
			taken <- ok
		}()
	}
	if first, second := <-taken, <-taken; first == second {
		t.Fatal("exactly one simultaneous save should claim the draft")
	}
}

func TestConnectionWizardEditIdentityAndRejectEngineError(t *testing.T) {
	f := newWizardFixture()
	f.cfg.Subscriptions = []subscription.Source{{ID: "vless", URL: "https://provider.example/source"}}
	f.cfg.Connections = []model.Connection{{ID: "existing", Type: model.ConnLink, Link: "socks5://existing.example:1080"}}
	h := New(f, setupTestOptions(RoleManage))
	checked, form := wizardCheck(t, h, "/connections/new", wizardLink+"#Main")
	if !strings.Contains(checked.Body.String(), `name="id" value="vless-2"`) {
		t.Fatal("suggested ID collides with the subscription")
	}
	cookies := checked.Result().Cookies()
	for _, id := range []string{"direct", "block", "vless", "existing", "Invalid", "-first", "subscription:vless:auto", strings.Repeat("a", 33)} {
		form.Set("id", id)
		oldToken := form.Get("preview")
		rejected := wizardPost(h, "/connections/new/save", form, cookies...)
		if rejected.Code != http.StatusUnprocessableEntity || f.applies != 0 {
			t.Fatalf("invalid ID %q returned HTTP %d", id, rejected.Code)
		}
		form.Set("preview", formField(t, rejected.Body.String(), "preview"))
		if oldToken == form.Get("preview") {
			t.Fatal("identity retry did not rotate its token")
		}
	}
	form.Set("id", "work_vpn-1")
	f.validateErr = errors.New("runtime exposed synthetic-engine-secret")
	w := wizardPost(h, "/connections/new/save", form, cookies...)
	if w.Code != http.StatusUnprocessableEntity || f.applies != 0 || strings.Contains(w.Body.String(), "synthetic-engine-secret") {
		t.Fatal("failed core validation applied the candidate or echoed raw error")
	}
}

func TestConnectionWizardViewer(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleView))
	for _, method := range []string{"paste", "file", "manual"} {
		w := setupRequest(h, "/connections/new?method="+method, nil)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), " disabled") {
			t.Fatalf("viewer %s form was not disabled: %d", method, w.Code)
		}
	}
	for _, route := range []string{"/connections/new/check", "/connections/new/save"} {
		form := url.Values{"rev": {Revision(f.cfg)}, "method": {"paste"}, "profile": {wizardLink}}
		if w := wizardPost(h, route, form); w.Code != http.StatusForbidden || f.validations != 0 || f.applies != 0 {
			t.Fatalf("forged viewer POST %s returned HTTP %d", route, w.Code)
		}
	}
}

func TestConnectionWizardFixedImportErrors(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	for _, tt := range []struct{ payload, message string }{
		{wizardConf + "PostUp=synthetic-secret", "Unsupported WireGuard option PostUp."},
		{wizardConf + "synthetic-secret=synthetic-key", translations["en"]["wizard_wg_unsupported"]},
		{`{"outbounds":[{"type":"trojan","password":"synthetic-secret"},{"type":"socks"}]}`, translations["en"]["wizard_json_multiple"]},
		{"secret-scheme://synthetic-key", translations["en"]["wizard_invalid"]},
	} {
		w := wizardPost(h, "/connections/new/check", url.Values{"rev": {Revision(f.Config())}, "method": {"paste"}, "profile": {tt.payload}})
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), tt.message) {
			t.Errorf("fixed message %q missing: HTTP %d", tt.message, w.Code)
		}
		for _, secret := range []string{"synthetic-secret", "synthetic-key", wizardWGKey} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("parse error exposed a credential")
			}
		}
	}
	if f.validations != 0 || f.applies != 0 {
		t.Fatal("parse refusals reached config validation or Apply")
	}
}

func TestConnectionWizardManualForms(t *testing.T) {
	for _, tt := range []struct{ protocol, label string }{
		{"vless", "VLESS"}, {"wireguard", "WireGuard"}, {"shadowsocks", "Shadowsocks"},
		{"trojan", "Trojan"}, {"hysteria2", "Hysteria2"}, {"socks", "SOCKS"},
	} {
		t.Run(tt.protocol, func(t *testing.T) {
			f := newWizardFixture()
			h := New(f, setupTestOptions(RoleManage))
			w := setupRequest(h, "/connections/new?method=manual&protocol="+tt.protocol, nil)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<option value="`+tt.protocol+`" selected>`) {
				t.Fatalf("could not select the manual form: HTTP %d", w.Code)
			}
			form := url.Values{
				"rev": {formField(t, w.Body.String(), "rev")}, "method": {"manual"}, "protocol": {tt.protocol},
				"server": {"vpn.example.test"}, "port": {"443"}, "security": {"tls"}, "uuid": {wizardUUID},
				"password": {"synthetic-secret"}, "username": {"fixture"}, "cipher": {"aes-128-gcm"},
				"privateKey": {wizardWGKey}, "peerKey": {wizardWGKey},
				"address": {"10.1.0.2/32"}, "endpoint": {"vpn.example.test:51820"},
			}
			checked := wizardPost(h, "/connections/new/check", form)
			if checked.Code != http.StatusOK || !strings.Contains(checked.Body.String(), "<dd>"+tt.label) {
				t.Fatalf("could not check the manual profile: HTTP %d", checked.Code)
			}
			for _, secret := range []string{"synthetic-secret", wizardUUID, wizardWGKey} {
				if strings.Contains(checked.Body.String(), secret) {
					t.Fatal("check exposed a manual credential")
				}
			}
			save := url.Values{"rev": form["rev"], "preview": {formField(t, checked.Body.String(), "preview")}, "id": {tt.protocol}, "name": {tt.label}}
			if got := wizardPost(h, "/connections/new/save", save, checked.Result().Cookies()...); got.Code != http.StatusSeeOther || f.applies != 1 || f.validations != 2 {
				t.Fatalf("could not save the checked profile: HTTP %d", got.Code)
			}
			c := f.cfg.Connections[0]
			if tt.protocol == model.ConnWireGuard {
				if c.WireGuard == nil || c.WireGuard.PrivateKey != wizardWGKey {
					t.Fatal("manual WireGuard did not keep its private key in config")
				}
			} else if c.Outbound["type"] != tt.protocol {
				t.Fatal("manual profile protocol changed on save")
			}
		})
	}
}

func TestConnectionWizardManualErrorPreservesSafeFields(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	form := url.Values{
		"rev": {Revision(f.Config())}, "method": {"manual"}, "protocol": {"vless"},
		"server": {"vpn.example.test"}, "port": {"443x"}, "security": {"tls"}, "sni": {"cover.example.test"},
		"flow": {"xtls-rprx-vision"}, "fingerprint": {"firefox"}, "uuid": {wizardUUID}, "publicKey": {"synthetic-key"},
	}
	bad := wizardPost(h, "/connections/new/check", form)
	body := bad.Body.String()
	for _, want := range []string{
		`value="vpn.example.test"`, `value="443x"`, `value="tls" selected`, `value="cover.example.test"`,
		`value="firefox"`, `aria-describedby="wizard-port-error"`, `id="wizard-port-error"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("manual correction lacks %s", want)
		}
	}
	if bad.Code != http.StatusUnprocessableEntity || strings.Contains(body, wizardUUID) || strings.Contains(body, "synthetic-key") || f.applies != 0 {
		t.Fatal("manual correction disclosed a credential or changed settings")
	}
	form.Set("port", "443")
	checked := wizardPost(h, "/connections/new/check", form)
	if checked.Code != http.StatusOK || !strings.Contains(checked.Body.String(), "VLESS · TLS") {
		t.Fatal("the corrected form should check with the selected TLS mode")
	}
}

func TestConnectionWizardKeepsAllowlistedVersionOnManualError(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	form := url.Values{
		"rev": {Revision(f.Config())}, "method": {"manual"}, "protocol": {"socks"}, "server": {"vpn.example.test"},
		"port": {"bad-port"}, "version": {"4a"}, "username": {"a"}, "password": {"synthetic-credential"},
	}
	w := wizardPost(h, "/connections/new/check", form)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `value="4a" selected`) ||
		strings.Contains(w.Body.String(), "synthetic-credential") {
		t.Fatal("manual correction lost a safe SOCKS version or exposed its password")
	}
}

func TestConnectionWizardAssociatesMalformedWireGuardKeysWithTheirFields(t *testing.T) {
	for _, field := range []string{"privateKey", "peerKey", "psk"} {
		t.Run(field, func(t *testing.T) {
			f := newWizardFixture()
			h := New(f, setupTestOptions(RoleManage))
			form := url.Values{
				"rev": {Revision(f.Config())}, "method": {"manual"}, "protocol": {"wireguard"},
				"privateKey": {wizardWGKey}, "peerKey": {wizardWGKey}, "psk": {wizardWGKey},
				"endpoint": {"vpn.example.test:51820"}, "address": {"10.1.0.2/32"},
			}
			form.Set(field, "synthetic-malformed-key")
			w := wizardPost(h, "/connections/new/check", form)
			if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `aria-describedby="wizard-`+field+`-error"`) ||
				!strings.Contains(w.Body.String(), `value="10.1.0.2/32"`) || strings.Contains(w.Body.String(), "synthetic-malformed-key") ||
				strings.Contains(w.Body.String(), wizardWGKey) {
				t.Fatal("the WireGuard field did not receive a safe, associated error")
			}
		})
	}
}

func TestConnectionWizardOversizedUploadKeepsReplaceEntry(t *testing.T) {
	f := newWizardFixture()
	const id = ".."
	f.cfg.Connections = []model.Connection{{ID: id, Name: "Home", Type: model.ConnLink, Link: "socks5://old.example:1080"}}
	h := New(f, setupTestOptions(RoleManage))
	entry := connectionDetailPath(id) + "/replace"
	checkForm := regexp.MustCompile(`<form class="wizard-input" method="post" action="([^"]+)"`)
	checkAction := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		match := checkForm.FindStringSubmatch(w.Body.String())
		if match == nil {
			t.Fatal("replacement upload form missing")
		}
		return html.UnescapeString(match[1])
	}
	upload := func(action, rev, payload string, chunked bool) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		m := multipart.NewWriter(&body)
		if err := m.WriteField("rev", rev); err != nil {
			t.Fatal(err)
		}
		if err := m.WriteField("method", "file"); err != nil {
			t.Fatal(err)
		}
		file, err := m.CreateFormFile("file", "client.conf")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, action, &body)
		req.Header.Set("Content-Type", m.FormDataContentType())
		if chunked {
			req.ContentLength = -1
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	get := setupRequest(h, entry+"?method=file", nil)
	rev := formField(t, get.Body.String(), "rev")
	action := checkAction(get)
	for _, chunked := range []bool{false, true} {
		oversized := upload(action, rev, strings.Repeat(" ", 3<<20), chunked)
		if oversized.Code != http.StatusRequestEntityTooLarge || !strings.Contains(oversized.Body.String(), "Replace connection") ||
			!strings.Contains(oversized.Body.String(), `type="file"`) || f.applies != 0 {
			t.Fatalf("large upload returned HTTP %d and lost the replacement (chunked %v)", oversized.Code, chunked)
		}
		action = checkAction(oversized)
	}
	checked := upload(action, rev, wizardConf, false)
	if checked.Code != http.StatusOK || !strings.Contains(checked.Body.String(), `value=".." readonly`) {
		t.Fatal("the smaller file was not checked as a replacement")
	}
	form := url.Values{"rev": {rev}, "name": {"Home"}, "preview": {formField(t, checked.Body.String(), "preview")}}
	saved := wizardPost(h, "/connections/new/save", form, checked.Result().Cookies()...)
	if saved.Code != http.StatusSeeOther || len(f.cfg.Connections) != 1 || f.cfg.Connections[0].ID != id || f.cfg.Connections[0].Type != model.ConnWireGuard {
		t.Fatalf("retry did not replace the original connection: HTTP %d", saved.Code)
	}
}

func TestConnectionWizardMultipartLimit(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	const max = 2 << 20
	for _, tt := range []struct{ size, status int }{{max, http.StatusOK}, {max + 1, http.StatusRequestEntityTooLarge}, {max * 2, http.StatusRequestEntityTooLarge}} {
		var body bytes.Buffer
		m := multipart.NewWriter(&body)
		if err := m.WriteField("rev", Revision(f.Config())); err != nil {
			t.Fatal(err)
		}
		if err := m.WriteField("method", "file"); err != nil {
			t.Fatal(err)
		}
		file, err := m.CreateFormFile("file", "client.conf")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(wizardConf + strings.Repeat(" ", tt.size-len(wizardConf)))); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/connections/new/check", &body)
		r.Header.Set("Content-Type", m.FormDataContentType())
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tt.status || strings.Contains(w.Body.String(), wizardWGKey) || f.applies != 0 {
			t.Fatalf("upload of %d bytes returned HTTP %d", tt.size, w.Code)
		}
		if w.Code == http.StatusOK && (formField(t, w.Body.String(), "name") != "WireGuard 1" ||
			formField(t, w.Body.String(), "id") != "wireguard") {
			t.Error("the uploaded filename influenced the suggested identity")
		}
	}
}

func TestConnectionWizardChoosesOneAmneziaProfile(t *testing.T) {
	f := newWizardFixture()
	h := New(f, setupTestOptions(RoleManage))
	candidate := func(server string) map[string]any {
		conf := strings.ReplaceAll(wizardConf, "vpn.example.test", server)
		return map[string]any{"container": "amnezia-awg2", "awg": map[string]any{"last_config": map[string]any{"config": conf}}}
	}
	encoded, err := json.Marshal(map[string]any{"containers": []any{candidate("first.example"), candidate("second.example")}})
	if err != nil {
		t.Fatal(err)
	}
	w, form := wizardCheck(t, h, "/connections/new", "vpn://"+base64.RawURLEncoding.EncodeToString(encoded))
	cookies := w.Result().Cookies()
	if !strings.Contains(w.Body.String(), "first.example:51820") || !strings.Contains(w.Body.String(), "second.example:51820") ||
		strings.Contains(w.Body.String(), wizardWGKey) || f.applies != 0 {
		t.Fatal("multi-profile check did not offer the two safe choices")
	}
	form.Set("id", "chosen")
	if got := wizardPost(h, "/connections/new/save", form, cookies...); got.Code != http.StatusConflict || f.applies != 0 {
		t.Fatal("Save accepted an unselected export")
	}
	form.Set("choice", "1")
	step := wizardPost(h, "/connections/new/check", form, cookies...)
	if step.Code != http.StatusOK || !strings.Contains(step.Body.String(), "second.example:51820") || strings.Contains(step.Body.String(), "first.example") {
		t.Fatalf("choice did not display just the selected profile: %d", step.Code)
	}
	form.Set("preview", formField(t, step.Body.String(), "preview"))
	if got := wizardPost(h, "/connections/new/save", form, cookies...); got.Code != http.StatusSeeOther || len(f.cfg.Connections) != 1 ||
		!strings.Contains(f.cfg.Connections[0].AmneziaWG, "second.example") {
		t.Fatal("only the selected Amnezia profile should be applied")
	}
}
