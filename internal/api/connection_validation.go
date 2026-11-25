package api

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

var profileUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

var serverProfileTypes = map[string]bool{"vless": true, "trojan": true, "shadowsocks": true, "hysteria2": true, "socks": true}
var passwordProfileTypes = map[string]bool{"trojan": true, "hysteria2": true, "shadowsocks": true}

func invalidProfileField(field string) error {
	return fmt.Errorf("invalid connection field format: %s", field)
}

// validWGKey requires a base64-encoded 32-byte WireGuard key.
func validWGKey(value string) bool {
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) == 32
}
func validateWGKeys(wg *model.WireGuard) error {
	if wg == nil {
		return nil
	}
	if !validWGKey(wg.PrivateKey) || !validWGKey(wg.Peer.PublicKey) {
		return invalidProfileField("WireGuard key")
	}
	if wg.Peer.PresharedKey != "" && !validWGKey(wg.Peer.PresharedKey) {
		return invalidProfileField("WireGuard key")
	}
	return nil
}
func profileString(out map[string]any, key string) string {
	value, _ := out[key].(string)
	return value
}

// validateOutboundFields enforces required fields that permissive engine decoding may accept.
func validateOutboundFields(out map[string]any) error {
	typ := profileString(out, "type")
	if serverProfileTypes[typ] {
		if profileString(out, "server") == "" {
			return invalidProfileField("server")
		}
		if out["server_port"] == nil {
			return invalidProfileField("server_port")
		}
	}
	if typ == "vless" && !profileUUID.MatchString(profileString(out, "uuid")) {
		return invalidProfileField("uuid")
	}
	if passwordProfileTypes[typ] && profileString(out, "password") == "" {
		return invalidProfileField("password")
	}
	return nil
}

// ValidateProfileFields checks required fields the engine parser may accept
// without sufficient parameters. A profile editor checks only its own input.
func ValidateProfileFields(connection model.Connection) error {
	if err := validateWGKeys(connection.WireGuard); err != nil {
		return err
	}
	return validateOutboundFields(connection.Outbound)
}
