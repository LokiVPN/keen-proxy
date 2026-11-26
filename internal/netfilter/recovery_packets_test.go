package netfilter

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestHandoffDNSOnlyAllowsFrontendInput(t *testing.T) {
	p := testPlan(model.InterceptRedirect)
	p.DNSListen = netip.MustParseAddrPort("192.168.7.1:53")
	rules := p.renderProtection()
	// Model INPUT after the PREROUTING DNS jump disappears at the handoff.
	for _, proto := range []string{"tcp", "udp"} {
		for _, tc := range []struct{ destination, want string }{
			{"192.168.7.1", "RETURN"}, // KeenProxy's address-specific frontend
			{"192.168.7.2", "DROP"},   // another resolver on the router
		} {
			packet := newRecoveryPacket(proto, tc.destination, "53")
			if got := recoveryPacketVerdict(t, rules, ChainDNSGuard, packet); got != tc.want {
				t.Errorf("INPUT %s DNS to %s = %s, want %s", proto, tc.destination, got, tc.want)
			}
		}
	}
}

func TestRecoveryPreservesPortForwardReplies(t *testing.T) {
	p := testPlan(model.InterceptRedirect)
	guard := p
	guard.DNSListen = netip.AddrPort{}
	for _, phase := range []struct{ name, rules string }{
		{"rollback guard", guard.renderProtection()},
		{"handoff guard", p.renderProtection()},
	} {
		t.Run(phase.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, state, direction, want string
				dnat                         bool
			}{
				{"new LAN connection", "NEW", "ORIGINAL", "DROP", false},
				{"reply from a port-forwarded LAN host", "ESTABLISHED", "REPLY", "RETURN", true},
				{"related traffic", "RELATED", "ORIGINAL", "RETURN", false},
				{"LAN-side original of a hairpin forward", "NEW", "ORIGINAL", "RETURN", true},
			} {
				packet := newRecoveryPacket("tcp", "203.0.113.8", "4443")
				packet.state, packet.direction, packet.dnat = tc.state, tc.direction, tc.dnat
				if got := recoveryPacketVerdict(t, phase.rules, ChainQUIC, packet); got != tc.want {
					t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
				}
			}
		})
	}
}

func TestTCPDNSStaysInterceptedWithoutDNSJump(t *testing.T) {
	// Model a clean daemon with PREROUTING dispatching only to ChainTCP.
	p := testPlan(model.InterceptRedirect)
	packet := newRecoveryPacket("tcp", "203.0.113.53", "53")
	rules := p.Render()
	if got := recoveryPacketVerdict(t, rules, ChainTCP, packet); got != "REDIRECT --to-ports 5354" {
		t.Fatalf("TCP DNS with only the TCP hook installed = %s, want REDIRECT", got)
	}
	var withoutDNS strings.Builder
	for line := range strings.SplitSeq(rules, "\n") {
		if !strings.HasPrefix(line, "-A "+ChainDNS+" ") {
			withoutDNS.WriteString(line + "\n")
		}
	}
	if got := recoveryPacketVerdict(t, withoutDNS.String(), ChainTCP, packet); got != "REDIRECT --to-ports 7901" {
		t.Fatalf("TCP DNS with DNS rules also missing = %s, want the TCP redirect", got)
	}
}

type recoveryPacket struct {
	source, destination        netip.Addr
	interfaceName, proto, port string
	state, direction           string
	dnat                       bool
}

func newRecoveryPacket(proto, destination, port string) recoveryPacket {
	return recoveryPacket{source: netip.MustParseAddr("192.168.7.104"), destination: netip.MustParseAddr(destination),
		interfaceName: "br0", proto: proto, port: port, state: "NEW", direction: "ORIGINAL"}
}

// recoveryPacketVerdict models the verdict of one owned chain. A case selects
// that chain through its hook and supplies the packet after routing and NAT.
func recoveryPacketVerdict(t *testing.T, rules, chain string, packet recoveryPacket) string {
	t.Helper()
	for line := range strings.SplitSeq(rules, "\n") {
		if !strings.HasPrefix(line, "-A "+chain+" ") {
			continue
		}
		args := strings.Fields(line)[2:]
		i := 0
		for i < len(args) && args[i] != "-j" {
			negated := args[i] == "!"
			if negated {
				i++
			}
			if packet.matches(t, args[i], args[i+1]) == negated {
				break
			}
			i += 2
		}
		if args[i] == "-j" {
			if args[i+1] == ChainDNS {
				if verdict := recoveryPacketVerdict(t, rules, ChainDNS, packet); verdict != "RETURN" {
					return verdict
				}
				continue
			}
			return strings.Join(args[i+1:], " ")
		}
	}
	return "RETURN"
}

func (p recoveryPacket) matches(t *testing.T, option, value string) bool {
	t.Helper()
	switch option {
	case "-m":
		return true
	case "-i":
		return p.interfaceName == value
	case "-s":
		return addressMatches(p.source, value)
	case "-d":
		return addressMatches(p.destination, value)
	case "-p":
		return p.proto == value
	case "--dport":
		return p.port == value
	case "--ctstate":
		return p.state == value || value == "DNAT" && p.dnat
	case "--ctdir":
		return p.direction == value
	default:
		t.Fatalf("unsupported packet match %q in fixture", option)
		return false
	}
}

func addressMatches(addr netip.Addr, match string) bool {
	if prefix, err := netip.ParsePrefix(match); err == nil {
		return prefix.Contains(addr)
	}
	return addr == netip.MustParseAddr(match)
}
