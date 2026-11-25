package connectionimport

import (
	"maps"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/awg"
	"github.com/ordo-systems/keen-proxy/internal/links"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// Facts is the public display projection of a saved profile. The original
// payload and credentials must be retrieved through the explicit reveal.
type Facts struct {
	Summary
	Transport, RoutingType string
	Addresses              []string
	TransportHidden        bool
}

// ConnectionFacts uses the stored options and the same parsers as compilation,
// so it can also describe a disabled profile that has no running outbound.
func ConnectionFacts(conn model.Connection) Facts {
	switch conn.Type {
	case model.ConnWireGuard:
		facts := Facts{Summary: Summary{Protocol: "WireGuard"}, Transport: "UDP"}
		if wg := conn.WireGuard; wg != nil {
			host, port, _ := net.SplitHostPort(wg.Peer.Endpoint)
			var secrets []string
			for _, key := range []string{wg.PrivateKey, wg.Peer.PublicKey, wg.Peer.PresharedKey} {
				secrets = appendCredentialForms(secrets, key)
			}
			facts.Server = displayAddress(host, port)
			facts.Summary = facts.Summary.hideRepeatedCredentials(wg.Peer.Endpoint, "", secrets)
			facts.TransportHidden = subscription.ContainsDisplaySecret(facts.Transport, secrets)
			facts.Addresses = detailAddresses(wg.Address, secrets)
		}
		return facts
	case model.ConnAmneziaWG:
		profile, _ := awg.Parse(conn.AmneziaWG)
		facts := savedProfileFacts(profile, true)
		facts.Protocol, facts.Transport = "AmneziaWG", "UDP"
		if addresses, ok := profile["address"].([]string); ok {
			facts.Addresses = detailAddresses(addresses, profileCredentials(profile, nil))
		}
		return facts
	case model.ConnLink, model.ConnTrustTunnel:
		link := conn.Link
		if conn.Type == model.ConnTrustTunnel && conn.TrustTunnel != nil {
			link = conn.TrustTunnel.Link
		}
		profile, _ := links.Parse(link)
		return savedProfileFacts(profile, false)
	default:
		if conn.Endpoint != nil {
			return savedProfileFacts(conn.Endpoint, true)
		}
		return savedProfileFacts(conn.Outbound, false)
	}
}

func savedProfileFacts(profile map[string]any, endpoint bool) Facts {
	// Both YAML/JSON endpoints and the compiler's AWG projection are maps,
	// with different slice types for peers.
	if peers, ok := profile["peers"].([]map[string]any); endpoint && ok && len(peers) == 1 {
		profile = maps.Clone(profile)
		profile["peers"] = []any{peers[0]}
	}
	facts := Facts{Summary: profileSummary(profile, endpoint)}
	rawServer, _ := profileAddress(profile, "server", "server_port")
	tls, _ := profile["tls"].(map[string]any)
	rawSNI, _ := tls["server_name"].(string)
	siblings := maps.Clone(profile)
	delete(siblings, "server")
	delete(siblings, "type")
	if tls != nil {
		siblings["tls"] = withoutDisplayFields(tls, "server_name")
	}
	transport, _ := profile["transport"].(map[string]any)
	if transport != nil {
		visible := withoutDisplayFields(transport, "type", "host")
		if headers, ok := transport["headers"].(map[string]any); ok {
			visible["headers"] = withoutDisplayFields(headers, "Host")
		}
		siblings["transport"] = visible
	}
	if peers, ok := profile["peers"].([]any); endpoint && ok && len(peers) == 1 {
		if peer, ok := peers[0].(map[string]any); ok {
			rawServer, _ = profileAddress(peer, "address", "port")
			siblings["peers"] = withoutDisplayFields(peer, "address")
		}
	}
	// Legacy options, nested headers and vendor extensions can hold additional
	// credentials. Suppress host facts that repeat any other profile string.
	secrets := detailProfileStrings(siblings, profileCredentials(profile, nil))
	facts.Summary = facts.Summary.hideDisplayType(secrets)
	if server, hidden := hideSummaryHost(facts.Server, rawServer, secrets); hidden {
		facts.Server, facts.ServerHidden = server, true
	}
	if sni, hidden := hideSummaryHost(facts.SNI, rawSNI, secrets); hidden {
		facts.SNI, facts.SNIHidden = sni, true
	}
	kind, _ := profile["type"].(string)
	switch kind {
	case "direct", "block", "selector", "urltest", "chain":
		facts.RoutingType = kind
	}
	mode, _ := transport["type"].(string)
	facts.Transport = detailTransport(kind, mode)
	facts.TransportHidden = subscription.ContainsDisplaySecret(facts.Transport, secrets)
	return facts
}

func withoutDisplayFields(options map[string]any, fields ...string) map[string]any {
	values := maps.Clone(options)
	for key := range values {
		if matchesCredentialField(key, fields) {
			delete(values, key)
		}
	}
	return values
}

func detailProfileStrings(value any, out []string) []string {
	switch value := value.(type) {
	case string:
		out = appendCredentialForms(out, value)
	case []string:
		for _, item := range value {
			out = appendCredentialForms(out, item)
		}
	case []any:
		for _, item := range value {
			out = detailProfileStrings(item, out)
		}
	case []map[string]any:
		for _, item := range value {
			out = detailProfileStrings(item, out)
		}
	case map[string]any:
		for key, field := range value {
			out = detailProfileStrings(field, out)
			if strings.EqualFold(key, "cookie") {
				for _, header := range credentialStrings(field) {
					cookies, _ := http.ParseCookie(header)
					for _, cookie := range cookies {
						out = appendCredentialForms(out, cookie.Value)
					}
				}
			}
		}
	}
	return out
}

func detailAddresses(addresses, secrets []string) []string {
	var out []string
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address); err == nil && !subscription.ContainsDisplaySecret(address, secrets) {
			out = append(out, prefix.String())
		}
	}
	return out
}

func detailTransport(kind, transport string) string {
	if label := detailTransportLabels[transport]; label != "" {
		return label
	}
	if transport == "" {
		switch kind {
		case "wireguard":
			return "UDP"
		case "hysteria", "hysteria2", "tuic", "masque":
			return "QUIC"
		case "trojan", "vless", "vmess":
			return "TCP"
		}
	}
	return ""
}

var detailTransportLabels = map[string]string{
	"tcp": "TCP", "ws": "WebSocket", "http": "HTTP", "httpupgrade": "HTTP Upgrade",
	"grpc": "gRPC", "quic": "QUIC", "xhttp": "XHTTP",
}
