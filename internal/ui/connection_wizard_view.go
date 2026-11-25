package ui

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/amnezia"
	"github.com/ordo-systems/keen-proxy/internal/connectionimport"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

type wizardLocation struct {
	method, protocol, replace string
}

type connectionWizardPage struct {
	Entry, Revision, Method, Protocol, Replace string
	Error, ChoiceToken                         string
	Choices                                    []wizardChoice
	Review                                     *wizardReview
	Fields, Advanced                           []wizardField
	Protocols                                  []wizardOption
}

type wizardReview struct {
	Token, Name, ID, NameError, IDError string
	Summary                             connectionimport.Summary
}

type wizardChoice struct {
	Index int
	Name  string
}

type wizardOption struct {
	Value, Label string
}

var wizardProtocols = []wizardOption{
	{"vless", "VLESS"}, {"wireguard", "WireGuard"}, {"shadowsocks", "Shadowsocks"},
	{"trojan", "Trojan"}, {"hysteria2", "Hysteria2"}, {"socks", "SOCKS"},
}

func wizardLocationFor(values url.Values) wizardLocation {
	loc := wizardLocation{method: "paste", protocol: "vless"}
	switch values.Get("method") {
	case "file", "manual":
		loc.method = values.Get("method")
	}
	if protocol := values.Get("protocol"); slices.ContainsFunc(wizardProtocols, func(p wizardOption) bool { return p.Value == protocol }) {
		loc.protocol = protocol
	}
	return loc
}

// wizardSuggestedName turns imported display labels into a bounded,
// single-line form suggestion. The underlying payload stays in the draft.
func wizardSuggestedName(draft connectionimport.Draft) string {
	name := strings.TrimSpace(draft.Connection.Name)
	count := 0
	for i := range name {
		if count == 160 {
			name = name[:i]
			break
		}
		count++
	}
	return cmp.Or(strings.Join(strings.Fields(name), " "), draft.Summary.Protocol)
}

func (p pages) renderConnectionWizard(w http.ResponseWriter, r *http.Request, status int, cfg *model.Config, loc wizardLocation, view connectionWizardPage) {
	data := p.opts.pageData(r)
	data.SignedIn, data.ViewOnly = true, p.role(r) == RoleView
	data.Title = data.Text["wizard_title"]
	view.Entry = "/connections/new"
	if loc.replace != "" && connectionIndex(cfg, loc.replace) >= 0 {
		data.Title = data.Text["wizard_replace"]
		view.Entry = connectionDetailPath(loc.replace) + "/replace"
		view.Replace = connectionIDSegment(loc.replace)
	}
	view.Method, view.Protocol, view.Revision = cmp.Or(loc.method, "paste"), loc.protocol, Revision(cfg)
	if view.Method == "manual" {
		view.Protocols = wizardProtocols
		view.Fields, view.Advanced = wizardManualFields(view.Protocol, data.Text)
	}
	data.ConnectionWizard = &view
	render(w, r, status, "connection-wizard", data)
}

func (p pages) wizardError(w http.ResponseWriter, r *http.Request, status int, cfg *model.Config, loc wizardLocation, key string) {
	p.renderConnectionWizard(w, r, status, cfg, loc, connectionWizardPage{Error: localized(r)[key]})
}

func (p pages) renderWizardChoices(w http.ResponseWriter, r *http.Request, status int, cfg *model.Config, draft connectionDraft, errorKey string) {
	token := p.connectionDrafts.put(draft, time.Now())
	if token == "" {
		p.wizardError(w, r, http.StatusConflict, cfg, draft.location, "wizard_check_again")
		return
	}
	choices := make([]wizardChoice, 0, len(draft.candidates))
	for i, candidate := range draft.candidates {
		name := wizardSuggestedName(candidate)
		if server := candidate.Summary.Server; server != "" {
			name += " · " + server
		}
		choices = append(choices, wizardChoice{Index: i, Name: name})
	}
	p.renderConnectionWizard(w, r, status, cfg, draft.location, connectionWizardPage{
		Choices: choices, ChoiceToken: token, Error: localized(r)[errorKey],
	})
}

func (p pages) renderWizardReview(w http.ResponseWriter, r *http.Request, status int, cfg *model.Config, draft connectionDraft, review wizardReview, errorKey string) {
	review.Token = p.connectionDrafts.put(draft, time.Now())
	if review.Token == "" {
		p.wizardError(w, r, http.StatusConflict, cfg, draft.location, "wizard_check_again")
		return
	}
	review.Summary = draft.candidates[0].Summary
	p.renderConnectionWizard(w, r, status, cfg, draft.location, connectionWizardPage{
		Review: &review, Error: localized(r)[errorKey],
	})
}

func wizardImportError(text map[string]string, err error) string {
	var wgOption connectionimport.UnsupportedWGOption
	var field connectionimport.ManualField
	switch {
	case errors.As(err, &wgOption):
		if wgOption == "" {
			return text["wizard_wg_unsupported"]
		}
		return fmt.Sprintf(text["wizard_wg_option"], string(wgOption))
	case errors.As(err, &field):
		return fmt.Sprintf(text["wizard_manual_error"], text["wizard_field_"+string(field)])
	case errors.Is(err, connectionimport.ErrTooLarge):
		return text["wizard_too_large"]
	case errors.Is(err, connectionimport.ErrMultiple):
		return text["wizard_json_multiple"]
	case errors.Is(err, connectionimport.ErrWGSections):
		return text["wizard_wg_sections"]
	case errors.Is(err, connectionimport.ErrInvalidDNS):
		return text["wizard_wg_dns"]
	case errors.Is(err, amnezia.ErrServiceProfile):
		return text["wizard_amnezia_service"]
	case errors.Is(err, amnezia.ErrAdminProfile):
		return text["wizard_amnezia_admin"]
	case errors.Is(err, amnezia.ErrUnsupportedProfile):
		return text["wizard_amnezia_unsupported"]
	case errors.Is(err, amnezia.ErrFormatVersion):
		return text["wizard_amnezia_version"]
	default:
		return text["wizard_invalid"]
	}
}

type wizardField struct {
	Key, Label, Type, Mode, Value, Placeholder string
	Wide                                       bool
	Options                                    []wizardOption
}

func wizardManualFields(protocol string, text map[string]string) ([]wizardField, []wizardField) {
	field := func(key string) wizardField {
		f := wizardField{Key: key, Label: text["wizard_field_"+key], Type: "text"}
		switch key {
		case "uuid", "password", "privateKey", "peerKey", "psk", "publicKey", "shortId":
			f.Type = "password"
		case "port", "mtu", "keepalive":
			f.Mode = "numeric"
		}
		switch key {
		case "uuid", "password", "privateKey", "address", "psk", "cipher", "version":
			f.Wide = true
		}
		return f
	}
	selectField := func(key string, options ...string) wizardField {
		f := field(key)
		for _, value := range options {
			f.Options = append(f.Options, wizardOption{Value: value, Label: value})
		}
		return f
	}
	if protocol == model.ConnWireGuard {
		address, endpoint := field("address"), field("endpoint")
		address.Placeholder, endpoint.Placeholder = "10.0.0.2/32", "vpn.example.net:51820"
		return []wizardField{field("privateKey"), address, endpoint, field("peerKey")},
			[]wizardField{field("psk"), field("mtu"), field("keepalive")}
	}

	server, port := field("server"), field("port")
	server.Placeholder, port.Value = "vpn.example.net", "443"
	fields := []wizardField{server, port}
	switch protocol {
	case "vless":
		security := field("security")
		security.Options = []wizardOption{{"reality", "REALITY"}, {"tls", "TLS"}, {"none", text["wizard_security_none"]}}
		sni := field("sni")
		sni.Placeholder = "www.example.com"
		fields = append(fields, field("uuid"), security, sni, field("publicKey"), field("shortId"))
		flow, fingerprint := field("flow"), field("fingerprint")
		flow.Value, fingerprint.Value = "xtls-rprx-vision", "chrome"
		return fields, []wizardField{flow, fingerprint}
	case "shadowsocks":
		fields = append(fields, field("password"), selectField("cipher",
			"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"))
	case "trojan", "hysteria2":
		fields = append(fields, field("password"), field("sni"))
	case "socks":
		fields[1].Value = "1080"
		password := field("password")
		password.Wide = false
		fields = append(fields, field("username"), password, selectField("version", "5", "4", "4a"))
	}
	return fields, nil
}
