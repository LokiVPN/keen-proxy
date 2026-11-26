package model

import (
	"net/netip"
)

// SchemaVersion is the configuration schema this release writes. Version 1
// files from older releases still load; those releases reject version 2.
const SchemaVersion = 2

// validateFeatures checks schema and DNS route safety.
func (c *Config) validateFeatures(add func(string, ...any)) {
	if c.SchemaVersion != 1 && c.SchemaVersion != SchemaVersion {
		add("schema_version: versions 1 and %d are supported, got %d", SchemaVersion, c.SchemaVersion)
	}
	d := c.DNS
	for i, source := range d.BypassSources {
		ip, err := netip.ParseAddr(source)
		if err != nil || !ip.Is4() || !(ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast()) {
			add("dns.bypass_sources[%d]: expected a unicast IPv4 address", i)
		}
	}
	if d.Route != "" && d.Route != "direct" && d.Route != "connection" {
		add("dns.route: expected direct or connection")
	}
	if d.Failure != "" && d.Failure != "strict" && d.Failure != "direct" {
		add("dns.failure: expected strict or direct")
	}
	if d.Route == "" && (d.Connection != "" || d.Failure != "") {
		add("dns.route: select a route explicitly")
	}
	if d.Route != "" {
		if len(d.Upstreams) == 0 {
			add("dns.upstreams: at least one server is required")
		}
		for _, raw := range d.Upstreams {
			u, e := ParseUpstream(raw)
			if e != nil {
				continue
			}
			if d.Route == "connection" && u.Kind == UpstreamUDP {
				add("dns: routing through a connection requires DoH or DoT")
			}
			if _, e := netip.ParseAddr(u.Host); e != nil {
				if _, e := netip.ParseAddr(d.Bootstrap[u.Host]); e != nil {
					add("dns.bootstrap: IP required for %s", u.Host)
				}
			}
		}
	}
	for host, ip := range d.Bootstrap {
		if _, e := netip.ParseAddr(ip); e != nil {
			add("dns.bootstrap[%s]: invalid IP", host)
		}
	}
	if d.Route == "connection" {
		// Routing containers may hide a direct exit under a non-reserved tag.
		for _, id := range c.Chain(d.Connection) {
			for _, cn := range c.Connections {
				if cn.ID == id && !dnsConnectionTypeCanTunnel(cn) {
					add("dns.connection: raw type %q does not guarantee a tunnel", rawConnectionType(cn))
				}
			}
		}

		found := false
		for _, cn := range c.Connections {
			if cn.ID == d.Connection {
				found = true
			}
		}
		if !found {
			add("dns.connection: unknown connection %q", d.Connection)
		}
		if d.Failure != "direct" {
			for _, id := range c.Chain(d.Connection) {
				if id == TargetDirect {
					add("dns: strict forbids direct in the connection chain")
				}
			}
		}
	} else if d.Connection != "" {
		add("dns.connection: only allowed with route=connection")
	}
}

func rawConnectionType(conn Connection) string {
	profile := conn.Outbound
	if conn.Endpoint != nil {
		profile = conn.Endpoint
	}
	kind, _ := profile["type"].(string)
	return kind
}

// For DNS, raw routing containers cannot guarantee a tunnel even when their
// configured target is not the built-in direct route.
func dnsConnectionTypeCanTunnel(conn Connection) bool {
	if conn.Type != ConnSingBox {
		return true
	}
	switch rawConnectionType(conn) {
	case "wireguard", "socks", "http", "shadowsocks", "vmess", "vless", "trojan", "tuic", "hysteria", "hysteria2", "ssh", "naive", "anytls":
		return true
	}
	return false
}
