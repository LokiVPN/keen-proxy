package connectionimport

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/awg"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

var (
	interfaceSection = regexp.MustCompile(`(?im)^[\t ]*\[Interface\][\t ]*(?:#[^\r\n]*)?\r?$`)
	awgSetting       = regexp.MustCompile(`(?im)^[\t ]*(?:Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RandomTrailers|DisableCookies|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|AdvancedSecurity)\s*=`)
	ErrInvalidDNS    = errors.New("invalid WireGuard DNS metadata")
	ErrWGSections    = errors.New("expected an Interface and one Peer")
)

// UnsupportedWGOption holds a fixed spelling for a known option. An unknown
// key has no display name because arbitrary text can contain credentials.
type UnsupportedWGOption string

func (o UnsupportedWGOption) Error() string {
	if o == "" {
		return "unsupported WireGuard option"
	}
	return "unsupported WireGuard option: " + string(o)
}

var knownWGOptions = map[string]UnsupportedWGOption{
	"privatekey": "PrivateKey", "address": "Address", "dns": "DNS", "mtu": "MTU", "listenport": "ListenPort",
	"publickey": "PublicKey", "presharedkey": "PresharedKey", "endpoint": "Endpoint", "allowedips": "AllowedIPs",
	"persistentkeepalive": "PersistentKeepalive", "fwmark": "FwMark", "table": "Table", "saveconfig": "SaveConfig",
	"preup": "PreUp", "predown": "PreDown", "postup": "PostUp", "postdown": "PostDown",
}

func importConf(raw, text, filename string) (Draft, error) {
	if awgSetting.MatchString(text) {
		for rawLine := range strings.SplitSeq(text, "\n") {
			line := confLine(rawLine)
			key, _, _ := strings.Cut(line, "=")
			switch name := strings.ToLower(strings.TrimSpace(key)); name {
			case "preup", "predown", "postup", "postdown", "fwmark", "table", "saveconfig":
				return Draft{}, knownWGOptions[name]
			}
		}
		return amneziaDraft(model.Connection{Type: model.ConnAmneziaWG, AmneziaWG: raw, Name: filename})
	}
	wg, err := parseWireGuard(text)
	if err != nil {
		return Draft{}, err
	}
	return importedIdentity(wireGuardDraft(wg), filename, []string{wg.PrivateKey, wg.Peer.PublicKey, wg.Peer.PresharedKey}), nil
}

func amneziaDraft(c model.Connection) (Draft, error) {
	endpoint, err := awg.Parse(c.AmneziaWG)
	if err != nil {
		return Draft{}, ErrInvalid
	}
	peer := endpoint["peers"].([]map[string]any)[0]
	draft := Draft{Connection: c, Summary: Summary{Protocol: "AmneziaWG", Server: profileAddress(peer, "address", "port")}}
	return importedIdentity(draft, c.Name, profileSecrets(endpoint)), nil
}

func wireGuardDraft(wg *model.WireGuard) Draft {
	host, port, _ := net.SplitHostPort(wg.Peer.Endpoint)
	return Draft{
		Connection: model.Connection{Type: model.ConnWireGuard, WireGuard: wg},
		Summary:    Summary{Protocol: "WireGuard", Server: displayAddress(host, port)},
	}
}

func confLine(raw string) string {
	line, _, _ := strings.Cut(raw, "#")
	return strings.TrimSpace(line)
}

func parseWireGuard(text string) (*model.WireGuard, error) {
	wg := &model.WireGuard{}
	var section string
	var seenPeer bool
	for raw := range strings.SplitSeq(text, "\n") {
		line := confLine(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			switch section {
			case "[interface]":
			case "[peer]":
				if seenPeer {
					return nil, ErrWGSections
				}
				seenPeer = true
			default:
				return nil, ErrWGSections
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, ErrInvalid
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if err := setWGField(wg, section, key, value); err != nil {
			return nil, err
		}
	}
	if wg.PrivateKey == "" || len(wg.Address) == 0 || wg.Peer.PublicKey == "" || wg.Peer.Endpoint == "" {
		return nil, ErrInvalid
	}
	return wg, nil
}

func setWGField(wg *model.WireGuard, section, key, value string) error {
	switch section + key {
	case "[interface]privatekey":
		wg.PrivateKey = strings.Clone(value)
	case "[interface]address":
		wg.Address = append(wg.Address, splitWGList(value, func(r rune) bool { return r == ',' })...)
	case "[interface]dns":
		// Check every assignment in order. DNS remains profile metadata.
		if awg.ValidateDNSMetadata(value) != nil {
			return ErrInvalidDNS
		}
	case "[interface]mtu":
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ErrInvalid
		}
		wg.MTU = uint32(n)
	case "[peer]publickey":
		wg.Peer.PublicKey = strings.Clone(value)
	case "[peer]presharedkey":
		wg.Peer.PresharedKey = strings.Clone(value)
	case "[peer]endpoint":
		host, port, err := net.SplitHostPort(value)
		if err != nil || displayAddress(host, port) == "" {
			return ErrInvalid
		}
		wg.Peer.Endpoint = strings.Clone(value)
	case "[peer]allowedips":
		wg.Peer.AllowedIPs = append(wg.Peer.AllowedIPs, splitWGList(value, func(r rune) bool { return r == ',' })...)
	case "[peer]persistentkeepalive":
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ErrInvalid
		}
		wg.Peer.Keepalive = uint16(n)
	default:
		return knownWGOptions[key]
	}
	return nil
}

func splitWGList(value string, separator func(rune) bool) []string {
	var list []string
	for _, item := range strings.FieldsFunc(value, separator) {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, strings.Clone(item))
		}
	}
	return list
}
