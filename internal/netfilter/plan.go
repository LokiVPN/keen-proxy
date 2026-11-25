// Package netfilter renders and applies kernel traffic interception rules.
//
// Rules use dedicated KEENPROXY_* chains loaded with iptables-restore --noflush
// atomically per table. Built-in chain jumps are installed idempotently, so
// Apply can restore rules after NDM rebuilds without touching unrelated rules.
package netfilter

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

const (
	ChainDNSGuard = "KEENPROXY_DNS_GUARD"
	ChainDNS      = "KEENPROXY_DNS"  // nat: LAN client DNS to the keenProxy frontend
	ChainTCP      = "KEENPROXY_TCP"  // nat: participating TCP to sing-box redirect inbound
	ChainUDP      = "KEENPROXY_UDP"  // mangle: participating UDP to sing-box TPROXY inbound
	ChainQUIC     = "KEENPROXY_QUIC" // filter: reject QUIC to encourage TCP fallback
)

// Plan contains interception inputs produced by internal/compile.
type Plan struct {
	BlockEncryptedDNS bool
	// GuardUnintercepted retains the guarded recovery filter on later installs.
	GuardUnintercepted bool
	Mode               model.InterceptMode
	LAN                string // client ingress interface, such as br0
	DNSPort            uint16
	TCPPort            uint16
	UDPPort            uint16
	FWMark             uint32
	// DNSBypassSources exempts only LAN TCP/UDP destination port 53.
	DNSBypassSources []netip.Addr
	// Sources lists participating addresses and networks; other devices bypass
	// userspace interception entirely.
	Sources []netip.Prefix
	// Excluded bypasses individual devices inside Sources (off mode).
	Excluded []netip.Addr
	// Bypass lists destinations that must never be intercepted.
	Bypass []netip.Prefix
}

// Jump connects a built-in chain to an owned interception chain.
type Jump struct {
	Table, From, To string
}

// DefaultBypass returns private, special-purpose, and multicast IPv4 ranges.
func DefaultBypass() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// Jumps returns installation order; each jump is inserted at the head of its chain.
func (p Plan) Jumps() []Jump {
	j := []Jump{
		{"nat", "PREROUTING", ChainTCP},
		{"nat", "PREROUTING", ChainDNS},
	}
	j = append(j, filterJumps()...)
	if p.Mode == model.InterceptTProxy {
		j = append(j, Jump{"mangle", "PREROUTING", ChainUDP})
	}
	return j
}

func (p Plan) preroutingJumps() []Jump {
	return slices.DeleteFunc(p.Jumps(), func(j Jump) bool { return j.Table == "filter" })
}

// The normal filter and the rollback guard share these hooks. Each filter
// restore replaces the chain contents without detaching the hooks.
func filterJumps() []Jump {
	return []Jump{
		{"filter", "FORWARD", ChainQUIC},
		{"filter", "INPUT", ChainDNSGuard},
		{"filter", "FORWARD", ChainDNSGuard},
	}
}

// Render builds iptables-restore --noflush input. Declaring a chain
// (":NAME - [0:0]") creates or flushes it without altering other chains.
func (p Plan) Render() string {
	var b strings.Builder
	p.renderPrerouting(&b)
	p.renderFilter(&b)
	return b.String()
}

func (p Plan) renderPrerouting(b *strings.Builder) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format+"\n", a...) }
	in := "-i " + p.LAN

	w("*nat")
	w(":%s - [0:0]", ChainDNS)
	w(":%s - [0:0]", ChainTCP)
	for _, source := range p.DNSBypassSources {
		src := host(source)
		for _, proto := range []string{"udp", "tcp"} {
			w("-A %s %s -s %s -p %s -m %s --dport 53 -j RETURN", ChainDNS, in, src, proto, proto)
		}
	}
	// DNS is intercepted only for participating sources; off devices and a
	// paused router keep talking to the KeeneticOS resolver directly.
	if len(p.Sources) > 0 {
		for _, e := range p.Excluded {
			w("-A %s %s -s %s -j RETURN", ChainDNS, in, host(e))
		}
		for _, s := range p.Sources {
			for _, proto := range []string{"udp", "tcp"} {
				w("-A %s %s -s %s -p %s -m %s --dport 53 -j REDIRECT --to-ports %d", ChainDNS, in, s, proto, proto, p.DNSPort)
			}
		}
	}
	if len(p.Sources) > 0 {
		for _, d := range p.Bypass {
			w("-A %s -d %s -j RETURN", ChainTCP, d)
		}
		for _, e := range p.Excluded {
			w("-A %s -s %s -j RETURN", ChainTCP, host(e))
		}
		// DNS owns port 53 regardless of the order of the two NAT hooks.
		w("-A %s %s -p tcp -m tcp --dport 53 -j RETURN", ChainTCP, in)
		for _, s := range p.Sources {
			w("-A %s %s -s %s -p tcp -j REDIRECT --to-ports %d", ChainTCP, in, s, p.TCPPort)
		}
	}
	w("COMMIT")

	if p.Mode == model.InterceptTProxy {
		mark := fmt.Sprintf("0x%x/0x%x", p.FWMark, p.FWMark)
		w("*mangle")
		w(":%s - [0:0]", ChainUDP)
		if len(p.Sources) > 0 {
			for _, d := range p.Bypass {
				w("-A %s -d %s -j RETURN", ChainUDP, d)
			}
			w("-A %s -p udp -m udp --dport 53 -j RETURN", ChainUDP)
			w("-A %s -p udp -m udp --dport 443 -j RETURN", ChainUDP) // QUIC is rejected in the filter table
			for _, e := range p.Excluded {
				w("-A %s -s %s -j RETURN", ChainUDP, host(e))
			}
			for _, s := range p.Sources {
				w("-A %s %s -s %s -p udp -j TPROXY --on-port %d --on-ip 127.0.0.1 --tproxy-mark %s",
					ChainUDP, in, s, p.UDPPort, mark)
			}
		}
		w("COMMIT")
	}
}

func (p Plan) renderFilter(b *strings.Builder) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format+"\n", a...) }
	in := "-i " + p.LAN
	w("*filter")
	w(":%s - [0:0]", ChainQUIC)
	w(":%s - [0:0]", ChainDNSGuard)
	if p.BlockEncryptedDNS && len(p.Sources) > 0 {
		for _, e := range p.Excluded {
			w("-A %s %s -s %s -j RETURN", ChainDNSGuard, in, host(e))
		}
		for _, s := range p.Sources {
			for _, proto := range []string{"tcp", "udp"} {
				w("-A %s %s -s %s -p %s --dport 853 -j REJECT", ChainDNSGuard, in, s, proto)
				w("-A %s %s -s %s -p %s -m conntrack --ctdir ORIGINAL --ctorigdstport 853 -j REJECT", ChainDNSGuard, in, s, proto)
			}
		}
	}
	for _, e := range p.Excluded {
		w("-A %s -s %s -j RETURN", ChainQUIC, host(e))
	}
	for _, s := range p.Sources {
		w("-A %s %s -s %s -p udp -m udp --dport 443 -j REJECT --reject-with icmp-port-unreachable", ChainQUIC, in, s)
	}
	if p.GuardUnintercepted && len(p.Sources) > 0 {
		p.renderHandoffDrops(b)
	}
	w("COMMIT")
}

// renderHandoffDrops keeps eligible packets from taking a direct path if
// firmware replaces prerouting between the entry checks and the filter commit.
// A successfully intercepted application packet never reaches FORWARD.
func (p Plan) renderHandoffDrops(b *strings.Builder) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format+"\n", a...) }
	in := "-i " + p.LAN
	dnsChain := ChainDNSGuard
	if p.DNSPort == 53 {
		// A live frontend on port 53 can receive local DNS on INPUT. Only
		// forwarded port 53 packets bypass that frontend in this case.
		dnsChain = ChainQUIC
	} else if !p.BlockEncryptedDNS {
		for _, addr := range p.Excluded {
			w("-A %s %s -s %s -j RETURN", ChainDNSGuard, in, host(addr))
		}
	}
	for _, addr := range p.DNSBypassSources {
		for _, proto := range []string{"tcp", "udp"} {
			w("-A %s %s -s %s -p %s --dport 53 -j RETURN", dnsChain, in, host(addr), proto)
		}
	}
	for _, source := range p.Sources {
		for _, proto := range []string{"tcp", "udp"} {
			w("-A %s %s -s %s -p %s --dport 53 -j DROP", dnsChain, in, source, proto)
		}
	}
	for _, dst := range p.Bypass {
		w("-A %s -d %s -j RETURN", ChainQUIC, dst)
	}
	for _, source := range p.Sources {
		w("-A %s %s -s %s -p tcp -m tcp ! --dport 53 -j DROP", ChainQUIC, in, source)
		if p.Mode == model.InterceptTProxy {
			w("-A %s %s -s %s -p udp -m udp ! --dport 53 -j DROP", ChainQUIC, in, source)
		}
	}
}

// renderProtection blocks public forwarding and DNS for covered clients if
// the previous interception plan could not be restored. LAN management and
// explicitly exempt devices and DNS sources keep their existing access.
func (p Plan) renderProtection() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("*filter")
	w(":%s - [0:0]", ChainQUIC)
	w(":%s - [0:0]", ChainDNSGuard)
	in := "-i " + p.LAN
	for _, addr := range p.Excluded {
		w("-A %s %s -s %s -j RETURN", ChainQUIC, in, host(addr))
		w("-A %s %s -s %s -j RETURN", ChainDNSGuard, in, host(addr))
	}
	for _, dst := range p.Bypass {
		w("-A %s -d %s -j RETURN", ChainQUIC, dst)
	}
	for _, addr := range p.DNSBypassSources {
		w("-A %s %s -s %s -j RETURN", ChainDNSGuard, in, host(addr))
		for _, proto := range []string{"udp", "tcp"} {
			w("-A %s %s -s %s -p %s --dport 53 -j RETURN", ChainQUIC, in, host(addr), proto)
		}
	}
	for _, src := range p.Sources {
		w("-A %s %s -s %s -j DROP", ChainQUIC, in, src)
		for _, proto := range []string{"udp", "tcp"} {
			w("-A %s %s -s %s -p %s --dport 53 -j DROP", ChainDNSGuard, in, src, proto)
		}
	}
	w("COMMIT")
	return b.String()
}

func host(a netip.Addr) string {
	return netip.PrefixFrom(a, a.BitLen()).String()
}
