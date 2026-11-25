package connectionimport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/amnezia"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

const wireGuardKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
const wireGuardConf = "[Interface]\nPrivateKey = " + wireGuardKey + "\nAddress = 10.1.0.2/32, 2001:db8:1::2/128\n" +
	"[Peer]\nPublicKey = " + wireGuardKey + "\nEndpoint = [2001:db8::1]:51820\n"

func TestParseWireGuard(t *testing.T) {
	conf := strings.Replace(wireGuardConf, "[Peer]", "DNS = 1.1.1.1, ::ffff:192.0.2.1, search.example.\nDNS=9.9.9.9\nMTU=1400\n[Peer]", 1)
	conf += "PresharedKey = " + wireGuardKey + "\nAllowedIPs=0.0.0.0/0, ::/0\nPersistentKeepalive=25 # seconds\n"
	drafts, err := Parse("\uFEFF"+strings.ReplaceAll(conf, "\n", "\r\n"), "home.CONF")
	if err != nil {
		t.Fatal(err)
	}
	want := &model.WireGuard{
		PrivateKey: wireGuardKey, Address: []string{"10.1.0.2/32", "2001:db8:1::2/128"}, MTU: 1400,
		Peer: model.WGPeer{Endpoint: "[2001:db8::1]:51820", PublicKey: wireGuardKey, PresharedKey: wireGuardKey,
			AllowedIPs: []string{"0.0.0.0/0", "::/0"}, Keepalive: 25},
	}
	if len(drafts) != 1 {
		t.Fatalf("imported %d WireGuard profiles", len(drafts))
	}
	c := drafts[0].Connection
	if c.Type != model.ConnWireGuard || c.Name != "home" || !reflect.DeepEqual(c.WireGuard, want) {
		t.Fatalf("unexpected WireGuard import")
	}
	if got := drafts[0].Summary; got.Protocol != "WireGuard" || got.Server != "[2001:db8::1]:51820" || got.SNI != "" {
		t.Fatalf("summary = %#v", got)
	}
	raw, err := json.Marshal(c)
	if err != nil || strings.Contains(string(raw), "search.example") || strings.Contains(string(raw), "9.9.9.9") {
		t.Fatal("DNS was persisted")
	}
}

func TestRejectWireGuardSettings(t *testing.T) {
	for _, tt := range []struct{ line, option string }{
		{"PostUp = secret-command", "PostUp"},
		{"PreUp = secret-command", "PreUp"},
		{"PreDown = secret-command", "PreDown"},
		{"PostDown = secret-command", "PostDown"},
		{"Table = secret-command", "Table"},
		{"DNS = secret-command", "DNS"},
		{"secret-option = secret-command", ""},
	} {
		_, err := Parse(wireGuardConf+tt.line, "")
		var option UnsupportedWGOption
		if !errors.As(err, &option) || string(option) != tt.option || strings.Contains(err.Error(), "secret-") {
			t.Fatalf("did not return the fixed option error for %q: %v", tt.option, err)
		}
	}
	for _, dns := range []string{"999.1.1.1", "192.168.001.1", "fe80::1%eth0", "1.1.1.1,", "bad..test", "https://resolver.test", ""} {
		_, err := Parse(strings.Replace(wireGuardConf, "[Peer]", "DNS="+dns+"\n[Peer]", 1), "")
		if !errors.Is(err, ErrInvalidDNS) {
			t.Errorf("DNS %q: %v", dns, err)
		}
	}
	for _, bad := range []string{
		wireGuardConf + "\n[Peer]\nPublicKey=more",
		strings.Replace(wireGuardConf, "[Peer]", "[Unknown]", 1),
		wireGuardConf + "\nPersistentKeepalive=65536",
		strings.Replace(wireGuardConf, ":51820", ":0", 1),
		strings.Replace(wireGuardConf, "Address = ", "# Address = ", 1),
	} {
		if _, err := Parse(bad, "profile.conf"); err == nil {
			t.Fatal("unsupported WireGuard profile accepted")
		}
	}
}

func TestParseAmneziaWGAndVPN(t *testing.T) {
	conf := "\uFEFF# Keep the original\r\n" + strings.ReplaceAll(
		strings.Replace(wireGuardConf, "[Peer]", "H1 = 100-200\nI1 = <b 0x1234>\n[Peer]", 1), "\n", "\r\n")
	drafts, err := Parse(conf, "standalone.txt")
	if err != nil || len(drafts) != 1 || drafts[0].Connection.AmneziaWG != conf || drafts[0].Summary.Server != "[2001:db8::1]:51820" {
		t.Fatalf("AWG was not detected and preserved: %v", err)
	}
	var option UnsupportedWGOption
	if _, err := Parse(conf+"PostUp=secret-command", ""); !errors.As(err, &option) || option != "PostUp" {
		t.Fatalf("AWG with a hook returned %v", err)
	}
	container := map[string]any{"container": "amnezia-awg2", "awg": map[string]any{"last_config": map[string]any{"config": conf}}}
	raw, err := json.Marshal(map[string]any{"format_version": 1, "containers": []any{container, container}})
	if err != nil {
		t.Fatal(err)
	}
	drafts, err = Parse("vpn://"+base64.RawURLEncoding.EncodeToString(raw), "client.vpn")
	if err != nil || len(drafts) != 2 {
		t.Fatalf("standalone export has %d candidates: %v", len(drafts), err)
	}
	for _, d := range drafts {
		if d.Connection.Type != model.ConnAmneziaWG || d.Summary.Server != "[2001:db8::1]:51820" {
			t.Fatal("standalone candidate did not contain the AWG profile")
		}
	}
	if _, err := Parse("vpn://invalid", ""); !errors.Is(err, amnezia.ErrInvalidProfile) {
		t.Fatalf("invalid standalone export returned %v", err)
	}
}

func TestParseSingBoxSingleProfile(t *testing.T) {
	raw := `{"dns":{"ignored":true},"route":{"final":"foreign"},"outbounds":[{"type":"direct","tag":"direct"},{"type":"trojan","tag":"work","server":"proxy.example","server_port":443,"password":"secret","tls":{"enabled":true,"server_name":"cover.example"}}]}`
	drafts, err := Parse(raw, "")
	if err != nil || len(drafts) != 1 {
		t.Fatalf("importable profiles = %d: %v", len(drafts), err)
	}
	d := drafts[0]
	if d.Connection.Name != "work" || d.Connection.Outbound["tag"] != nil || d.Connection.Outbound["route"] != nil ||
		d.Connection.Outbound["password"] != "secret" || d.Summary.Server != "proxy.example:443" || d.Summary.SNI != "cover.example" {
		t.Fatal("sing-box import changed profile options or included global settings")
	}
	for _, raw := range []string{`{"type":"wireguard"}`, `{"endpoint":{"type":"wireguard"}}`, `{"endpoints":[{"type":"wireguard"}]}`} {
		drafts, err := Parse(raw, "client.json")
		if err != nil || len(drafts) != 1 || drafts[0].Connection.Endpoint["type"] != "wireguard" {
			t.Fatalf("endpoint import failed: %v", err)
		}
	}
	for _, raw := range []string{
		`{"outbounds":[{"type":"trojan"},{"type":"socks"}]}`,
		`{"outbound":{"type":"trojan"},"endpoint":{"type":"wireguard"}}`,
	} {
		if _, err := Parse(raw, ""); !errors.Is(err, ErrMultiple) {
			t.Errorf("multiple importable profiles returned %v", err)
		}
	}
	for _, raw := range []string{`[]`, `{"outbounds":null}`, `{"outbounds":{}}`, `{"outbound":{}}`, `{"type":2}`, `{"type":"selector"}`} {
		if _, err := Parse(raw, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("malformed profile returned %v", err)
		}
	}
}

func TestParseConnectionLink(t *testing.T) {
	const link = "vless://00000000-0000-4000-8000-000000000000@vpn.example.test:443?security=reality&sni=cover.example.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#Work%20VPN"
	atLimit := link + strings.Repeat(" ", MaxSize-len(link))
	drafts, err := Parse(atLimit, "ignored.txt")
	if err != nil || len(drafts) != 1 {
		t.Fatalf("link at size limit: %v", err)
	}
	d := drafts[0]
	if c := d.Connection; c.Type != model.ConnLink || c.Name != "Work VPN" || c.Link != link {
		t.Fatal("share link or its display name was changed")
	}
	if got := d.Summary; got != (Summary{Protocol: "VLESS", Security: "REALITY", Server: "vpn.example.test:443", SNI: "cover.example.test"}) {
		t.Fatalf("summary = %#v", got)
	}
	if _, err := Parse(atLimit+" ", ""); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over-limit link returned %v", err)
	}
	if _, err := Parse("unsupported-secret://private", ""); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe failure: %v", err)
	}
}

func TestBuildManualProtocols(t *testing.T) {
	fields := url.Values{
		"server": {"vpn.example.test"}, "port": {"443"}, "uuid": {"00000000-0000-4000-8000-000000000000"},
		"security": {"reality"}, "sni": {"cover.example.test"}, "publicKey": {strings.Repeat("A", 43)}, "shortId": {"ab12"},
		"flow": {"xtls-rprx-vision"}, "fingerprint": {"firefox"}, "cipher": {"aes-128-gcm"}, "username": {"operator"},
		"password": {" synthetic-secret "}, "version": {"4a"}, "privateKey": {wireGuardKey}, "peerKey": {wireGuardKey},
		"address": {"10.1.0.2/32, 2001:db8::1/128"}, "endpoint": {"vpn.example.test:51820"}, "psk": {wireGuardKey},
		"mtu": {"1400"}, "keepalive": {"25"},
	}
	for _, p := range []string{"wireguard", "vless", "shadowsocks", "trojan", "hysteria2", "socks"} {
		t.Run(p, func(t *testing.T) {
			fields.Set("protocol", p)
			d, err := Manual(fields)
			if err != nil {
				t.Fatal(err)
			}
			if p == "wireguard" {
				wg := d.Connection.WireGuard
				if wg.MTU != 1400 || wg.Peer.Keepalive != 25 || wg.Peer.PresharedKey != wireGuardKey || len(wg.Address) != 2 {
					t.Fatal("manual WG lost optional fields")
				}
				return
			}
			o := d.Connection.Outbound
			if o["type"] != p || (p != "vless" && o["uuid"] != nil) {
				t.Fatal("manual configuration imported fields from another protocol")
			}
			switch p {
			case "vless":
				tls := o["tls"].(map[string]any)
				if o["flow"] != "xtls-rprx-vision" || tls["utls"].(map[string]any)["fingerprint"] != "firefox" ||
					tls["reality"].(map[string]any)["short_id"] != "ab12" {
					t.Fatal("manual REALITY lost its options")
				}
			case "shadowsocks":
				if o["method"] != "aes-128-gcm" || o["password"] != fields.Get("password") || o["tls"] != nil {
					t.Fatal("manual Shadowsocks payload is incorrect")
				}
			case "trojan", "hysteria2":
				if o["password"] != fields.Get("password") || d.Summary.SNI != "cover.example.test" {
					t.Fatal("manual TLS password or SNI changed")
				}
			case "socks":
				if o["username"] != "operator" || o["version"] != "4a" || o["password"] != fields.Get("password") || o["tls"] != nil {
					t.Fatal("SOCKS credentials or version changed")
				}
			}
		})
	}
	fields.Set("protocol", "vless")
	for _, security := range []string{"none", "tls"} {
		fields.Set("sni", "")
		fields.Set("security", security)
		d, err := Manual(fields)
		if err != nil {
			t.Fatal(err)
		}
		if security == "none" && d.Connection.Outbound["tls"] != nil || security == "tls" && d.Summary.SNI != fields.Get("server") {
			t.Fatalf("manual security %q changed", security)
		}
	}
	for _, port := range []string{"0", "65536", "443x", "+443"} {
		fields.Set("port", port)
		if _, err := Manual(fields); err != ManualField("port") {
			t.Errorf("invalid port returned %v", err)
		}
	}
}

func TestSuggestID(t *testing.T) {
	for name, want := range map[string]string{
		"  Work - VPN__42! ": "work-vpn-42",
		"\u0420\u0430\u0431\u043e\u0447\u0438\u0439 \u0441\u0435\u0440\u0432\u0435\u0440": "rabochiy-server",
		strings.Repeat("u", 40): strings.Repeat("u", 32),
	} {
		if got := Slug(name); got != want {
			t.Errorf("slug = %q, want %q", got, want)
		}
	}
}
