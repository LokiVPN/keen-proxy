package connectionimport

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"

	"golang.org/x/net/idna"
)

// Summary is the allowlisted projection for the check screen. Protocol is an
// application-owned label shared by both locales.
type Summary struct {
	Protocol, Security, Server, SNI string
}

var protocolLabel = map[string]string{
	"wireguard": "WireGuard", "vless": "VLESS", "vmess": "VMess", "shadowsocks": "Shadowsocks",
	"trojan": "Trojan", "hysteria2": "Hysteria2", "socks": "SOCKS", "tuic": "TUIC",
	"anytls": "AnyTLS", "trusttunnel": "TrustTunnel", "hysteria": "Hysteria",
	"snell": "Snell", "shadowtls": "ShadowTLS", "masque": "MASQUE",
	"ssh": "SSH", "http": "HTTP", "naive": "Naive", "tailscale": "Tailscale",
	"openvpn": "OpenVPN", "openconnect": "OpenConnect", "tor": "Tor", "bridge": "Bridge",
}

func outboundSummary(out map[string]any) Summary {
	summary := Summary{Protocol: displayProtocol(out), Server: profileAddress(out, "server", "server_port")}
	tls, _ := out["tls"].(map[string]any)
	if tls["enabled"] == true {
		summary.Security = "TLS"
		reality, _ := tls["reality"].(map[string]any)
		if reality["enabled"] == true {
			summary.Security = "REALITY"
		}
		if name, ok := tls["server_name"].(string); ok {
			summary.SNI = displayHost(name)
		}
	}
	return summary
}

func endpointSummary(endpoint map[string]any) Summary {
	summary := outboundSummary(endpoint)
	if peers, ok := endpoint["peers"].([]any); ok && len(peers) == 1 {
		if peer, ok := peers[0].(map[string]any); ok {
			summary.Server = profileAddress(peer, "address", "port")
		}
	}
	return summary
}

func displayProtocol(profile map[string]any) string {
	kind, _ := profile["type"].(string)
	if label := protocolLabel[kind]; label != "" {
		return label
	}
	return "sing-box"
}

func profileAddress(profile map[string]any, serverKey, portKey string) string {
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
		return displayHost(host)
	}
	return displayAddress(host, port)
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
