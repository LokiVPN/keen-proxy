package connectionimport

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"

	"golang.org/x/net/idna"

	"github.com/ordo-systems/keen-proxy/internal/profiledisplay"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// Summary is the allowlisted projection for the check screen. Protocol is an
// application-owned label shared by both locales.
type Summary struct {
	Protocol, Security, Server, SNI     string
	TypeHidden, ServerHidden, SNIHidden bool
}

var protocolLabel = map[string]string{
	"wireguard": "WireGuard", "vless": "VLESS", "vmess": "VMess", "shadowsocks": "Shadowsocks",
	"trojan": "Trojan", "hysteria2": "Hysteria2", "socks": "SOCKS", "tuic": "TUIC",
	"anytls": "AnyTLS", "trusttunnel": "TrustTunnel", "hysteria": "Hysteria",
	"snell": "Snell", "shadowtls": "ShadowTLS", "masque": "MASQUE",
	"ssh": "SSH", "http": "HTTP", "naive": "Naive", "tailscale": "Tailscale",
	"openvpn": "OpenVPN", "openconnect": "OpenConnect", "tor": "Tor", "bridge": "Bridge",
}

func profileSummary(profile map[string]any, endpoint bool) Summary {
	summary, rawServer, sni := profileSummaryValues(profile, endpoint)
	return summary.hideRepeatedCredentials(rawServer, sni, profiledisplay.Credentials(profile))
}

func profileSummaryValues(profile map[string]any, endpoint bool) (Summary, string, string) {
	rawServer, server := profileAddress(profile, "server", "server_port")
	if peers, ok := profile["peers"].([]any); endpoint && ok && len(peers) == 1 {
		if peer, ok := peers[0].(map[string]any); ok {
			rawServer, server = profileAddress(peer, "address", "port")
		}
	}
	summary := Summary{Protocol: displayProtocol(profile), Server: server}
	var sni string
	tls, _ := profile["tls"].(map[string]any)
	if tls["enabled"] == true {
		summary.Security = "TLS"
		reality, _ := tls["reality"].(map[string]any)
		if reality["enabled"] == true {
			summary.Security = "REALITY"
		}
		sni, _ = tls["server_name"].(string)
		summary.SNI = displayHost(sni)
	}
	return summary, rawServer, sni
}

// Compare the input and the display form of each host so canonicalization
// cannot turn a repeated credential into a visible hostname.
func (s Summary) hideRepeatedCredentials(rawServer, rawSNI string, credentials []string) Summary {
	s = s.hideDisplayType(credentials)
	s.Server, s.ServerHidden = hideSummaryHost(s.Server, rawServer, credentials)
	s.SNI, s.SNIHidden = hideSummaryHost(s.SNI, rawSNI, credentials)
	return s
}

func (s Summary) hideDisplayType(credentials []string) Summary {
	typ := s.Protocol
	if s.Security != "" {
		typ += " · " + s.Security
	}
	s.TypeHidden = s.TypeHidden || subscription.ContainsDisplaySecret(typ, credentials)
	return s
}

func hideSummaryHost(value, raw string, credentials []string) (string, bool) {
	if value != "" && (subscription.ContainsDisplaySecret(value, credentials) ||
		raw != value && subscription.ContainsDisplaySecret(raw, credentials)) {
		return "", true
	}
	return value, false
}

func displayProtocol(profile map[string]any) string {
	kind, _ := profile["type"].(string)
	if label := protocolLabel[kind]; label != "" {
		return label
	}
	return "sing-box"
}

func profileAddress(profile map[string]any, serverKey, portKey string) (raw, display string) {
	host, _ := profile[serverKey].(string)
	var port string
	switch value := profile[portKey].(type) {
	case int:
		port = strconv.Itoa(value)
	case uint64:
		port = strconv.FormatUint(value, 10)
	case float64:
		port = strconv.FormatFloat(value, 'f', -1, 64)
	}
	if port == "" {
		return host, displayHost(host)
	}
	return net.JoinHostPort(host, port), displayAddress(host, port)
}

func displayAddress(host, port string) string {
	n, err := strconv.ParseUint(port, 10, 16)
	if host = displayHost(host); host == "" || err != nil || n == 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.FormatUint(n, 10))
}

var domainShape = regexp.MustCompile(`^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.?$`)

// displayHost accepts an IP or hostname alone, so a value containing a URL,
// user information, query string or other profile text cannot reach the page.
func displayHost(host string) string {
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return ip.String()
	}
	if len(host) > 253 {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || len(ascii) > 253 || !domainShape.MatchString(ascii) {
		return ""
	}
	return ascii
}
