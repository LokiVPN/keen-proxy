package connectionimport

import (
	"maps"
	"net"
	"net/netip"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/awg"
	"github.com/ordo-systems/keen-proxy/internal/links"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Facts is the public display projection of a saved profile. The original
// payload and credentials must be retrieved through the explicit reveal.
type Facts struct {
	Summary
	Transport, RoutingType           string
	Addresses                        []string
	TransportHidden, AddressesHidden bool
}

// ConnectionFacts uses the stored options and the same parsers as compilation,
// so it can also describe a disabled profile that has no running outbound.
func ConnectionFacts(conn model.Connection) Facts {
	switch conn.Type {
	case model.ConnWireGuard:
		facts := Facts{Summary: Summary{Protocol: "WireGuard"}, Transport: "UDP"}
		if wg := conn.WireGuard; wg != nil {
			host, port, _ := net.SplitHostPort(wg.Peer.Endpoint)
			leaves := profileDisplayStrings(wg)
			facts.Server = displayAddress(host, port)
			facts.TypeHidden = repeatsProfileString(leaves, nil, facts.Protocol)
			facts.TransportHidden = repeatsProfileString(leaves, nil, facts.Transport)
			facts.ServerHidden = facts.Server != "" && repeatsProfileString(leaves, []string{"Peer", "Endpoint"}, facts.Server, wg.Peer.Endpoint, host)
			if facts.ServerHidden {
				facts.Server = ""
			}
			facts.setAddresses(wg.Address, leaves, "Address")
		}
		return facts
	case model.ConnAmneziaWG:
		profile, _ := awg.Parse(conn.AmneziaWG)
		return savedProfileFacts(profile, true, "AmneziaWG")
	case model.ConnLink, model.ConnTrustTunnel:
		link := conn.Link
		if conn.Type == model.ConnTrustTunnel && conn.TrustTunnel != nil {
			link = conn.TrustTunnel.Link
		}
		profile, _ := links.Parse(link)
		return savedProfileFacts(profile, false, "")
	default:
		if conn.Endpoint != nil {
			return savedProfileFacts(conn.Endpoint, true, "")
		}
		return savedProfileFacts(conn.Outbound, false, "")
	}
}

func savedProfileFacts(profile map[string]any, endpoint bool, protocol string) Facts {
	// Both YAML/JSON endpoints and the compiler's AWG projection are maps,
	// with different slice types for peers.
	if peers, ok := profile["peers"].([]map[string]any); endpoint && ok && len(peers) == 1 {
		profile = maps.Clone(profile)
		profile["peers"] = []any{peers[0]}
	}
	summary, rawServer, rawSNI := profileSummaryValues(profile, endpoint)
	if protocol != "" {
		summary.Protocol = protocol
	}
	facts := Facts{Summary: summary}
	leaves := profileDisplayStrings(profile)
	kind, _ := profile["type"].(string)
	typ := facts.Protocol
	if facts.Security != "" {
		typ += " · " + facts.Security
	}
	facts.TypeHidden = repeatsProfileString(leaves, []string{"type"}, typ, kind)
	switch kind {
	case "direct", "block", "selector", "urltest", "chain":
		facts.RoutingType = kind
	}
	serverPath := []string{"server"}
	host, _ := profile["server"].(string)
	if peers, ok := profile["peers"].([]any); endpoint && ok && len(peers) == 1 {
		if peer, ok := peers[0].(map[string]any); ok {
			serverPath = []string{"peers", "0", "address"}
			host, _ = peer["address"].(string)
		}
	}
	facts.ServerHidden = facts.Server != "" && repeatsProfileString(leaves, serverPath, facts.Server, rawServer, host)
	if facts.ServerHidden {
		facts.Server = ""
	}
	facts.SNIHidden = facts.SNI != "" && repeatsProfileString(leaves, []string{"tls", "server_name"}, facts.SNI, rawSNI)
	if facts.SNIHidden {
		facts.SNI = ""
	}
	transport, _ := profile["transport"].(map[string]any)
	mode, _ := transport["type"].(string)
	facts.Transport = detailTransport(kind, mode)
	if protocol == "AmneziaWG" {
		facts.Transport = "UDP"
	}
	if facts.Transport != "" {
		facts.TransportHidden = repeatsProfileString(leaves, []string{"transport", "type"}, facts.Transport, mode)
	}
	if endpoint {
		facts.setAddresses(credentialStrings(profile["address"]), leaves, "address")
	}
	return facts
}

func (f *Facts) setAddresses(addresses []string, leaves []profileString, field string) {
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address); err == nil {
			f.Addresses = append(f.Addresses, prefix.String())
			f.AddressesHidden = f.AddressesHidden || repeatsProfileString(leaves, []string{field}, address, prefix.String())
		}
	}
	f.AddressesHidden = f.AddressesHidden || repeatsProfileString(leaves, []string{field}, strings.Join(f.Addresses, ", "))
	if f.AddressesHidden {
		f.Addresses = nil
	}
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
