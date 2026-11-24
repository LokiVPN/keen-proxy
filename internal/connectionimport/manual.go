package connectionimport

import (
	"cmp"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// ManualField identifies an invalid input using the form's fixed field name.
type ManualField string

func (f ManualField) Error() string { return "invalid manual connection field: " + string(f) }

// Manual builds a draft from the active protocol's fields. The name, ID,
// engine validation and application remain the responsibility of the caller.
func Manual(f url.Values) (Draft, error) {
	protocol := f.Get("protocol")
	if protocol == model.ConnWireGuard {
		return manualWireGuard(f)
	}
	switch protocol {
	case "vless", "shadowsocks", "trojan", "hysteria2", "socks":
	default:
		return Draft{}, ManualField("protocol")
	}
	host := strings.TrimSpace(f.Get("server"))
	if displayHost(host) == "" {
		return Draft{}, ManualField("server")
	}
	port, err := strconv.ParseUint(f.Get("port"), 10, 16)
	if err != nil || port == 0 {
		return Draft{}, ManualField("port")
	}
	out := map[string]any{"type": protocol, "server": host, "server_port": int(port)}
	switch protocol {
	case "vless":
		if err := manualVLESS(f, out, host); err != nil {
			return Draft{}, err
		}
	case "socks":
		version := cmp.Or(f.Get("version"), "5")
		if version != "5" && version != "4" && version != "4a" {
			return Draft{}, ManualField("version")
		}
		out["version"] = version
		if user := f.Get("username"); user != "" {
			out["username"], out["password"] = user, f.Get("password")
		}
	default:
		if password := f.Get("password"); strings.TrimSpace(password) != "" {
			out["password"] = password
		} else {
			return Draft{}, ManualField("password")
		}
		if protocol == "shadowsocks" {
			if method := f.Get("cipher"); strings.TrimSpace(method) != "" {
				out["method"] = method
			} else {
				return Draft{}, ManualField("cipher")
			}
		} else {
			out["tls"] = manualTLS(f, host)
		}
	}
	return Draft{
		Connection: model.Connection{Type: model.ConnSingBox, Outbound: out},
		Summary:    outboundSummary(out),
	}, nil
}

var (
	vlessUUID    = regexp.MustCompile(`(?i)^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
	realityKey   = regexp.MustCompile(`^[a-zA-Z0-9_-]{43}$`)
	realityShort = regexp.MustCompile(`(?i)^([0-9a-f]{2}){0,8}$`)
)

func manualVLESS(f url.Values, out map[string]any, host string) error {
	uuid := strings.TrimSpace(f.Get("uuid"))
	if !vlessUUID.MatchString(uuid) {
		return ManualField("uuid")
	}
	out["uuid"] = uuid
	if flow := f.Get("flow"); flow != "" {
		out["flow"] = flow
	}
	tls := manualTLS(f, host)
	switch f.Get("security") {
	case "none":
		return nil
	case "", "tls":
	case "reality":
		if strings.TrimSpace(f.Get("sni")) == "" {
			return ManualField("sni")
		}
		key, short := f.Get("publicKey"), f.Get("shortId")
		if !realityKey.MatchString(key) {
			return ManualField("publicKey")
		}
		if !realityShort.MatchString(short) {
			return ManualField("shortId")
		}
		tls["reality"] = map[string]any{"enabled": true, "public_key": key, "short_id": short}
	default:
		return ManualField("security")
	}
	tls["utls"] = map[string]any{"enabled": true, "fingerprint": cmp.Or(f.Get("fingerprint"), "chrome")}
	out["tls"] = tls
	return nil
}

func manualTLS(f url.Values, host string) map[string]any {
	return map[string]any{"enabled": true, "server_name": cmp.Or(strings.TrimSpace(f.Get("sni")), host)}
}

func manualWireGuard(f url.Values) (Draft, error) {
	wg := &model.WireGuard{}
	for _, field := range []struct {
		name string
		dest *string
	}{
		{"privateKey", &wg.PrivateKey}, {"peerKey", &wg.Peer.PublicKey}, {"endpoint", &wg.Peer.Endpoint},
	} {
		*field.dest = strings.TrimSpace(f.Get(field.name))
		if *field.dest == "" {
			return Draft{}, ManualField(field.name)
		}
	}
	host, port, err := net.SplitHostPort(wg.Peer.Endpoint)
	if err != nil || displayAddress(host, port) == "" {
		return Draft{}, ManualField("endpoint")
	}
	wg.Address = splitWGList(f.Get("address"), func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(wg.Address) == 0 {
		return Draft{}, ManualField("address")
	}
	wg.Peer.PresharedKey = strings.TrimSpace(f.Get("psk"))
	if value := f.Get("mtu"); value != "" {
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return Draft{}, ManualField("mtu")
		}
		wg.MTU = uint32(n)
	}
	if value := f.Get("keepalive"); value != "" {
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return Draft{}, ManualField("keepalive")
		}
		wg.Peer.Keepalive = uint16(n)
	}
	return wireGuardDraft(wg), nil
}
