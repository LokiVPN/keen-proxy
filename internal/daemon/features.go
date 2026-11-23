package daemon

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/dnsfront"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	M "github.com/sagernet/sing/common/metadata"
)

// DNSInfo summarizes the latest DNS route and cumulative fallback and block counts.
type DNSInfo struct {
	Route     string    `json:"route"`
	Checked   time.Time `json:"checked"`
	Fallbacks uint64    `json:"fallbacks"`
	Blocked   uint64    `json:"blocked"`
}

// DNSInfo returns the last resolver check under the feature-state lock.
func (d *Daemon) DNSInfo() DNSInfo { d.featureMu.Lock(); defer d.featureMu.Unlock(); return d.dnsInfo }

// managedConn releases dial-context resources exactly once when closed.
type managedConn struct {
	net.Conn
	once sync.Once
	done func()
}

// Close closes the socket and releases its cancellation bridge on the first call.
func (c *managedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.done); return err }

// dnsDial follows a connection selector but rejects direct exits; direct DNS fallback
// uses the separate explicit resolver policy.
func (d *Daemon) dnsDial(id string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		tag := id
		cfg := d.live.Load()
		if cfg != nil {
			for _, cn := range cfg.Connections {
				if cn.ID == id && (cn.Fallback != "" || cn.Disabled) {
					tag = compile.FailoverTagPrefix + id
				}
			}
		}
		out, engCtx, ok := d.eng.Outbound(tag)
		if !ok {
			return nil, fmt.Errorf("DNS connection %s is not running", id)
		}
		if stats.Resolve(out).Tag() == model.TargetDirect {
			return nil, fmt.Errorf("DNS: direct in connection chain, use an explicit fallback")
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}
		dctx, cancel := context.WithCancel(engCtx)
		if deadline, ok := ctx.Deadline(); ok {
			cancel()
			dctx, cancel = context.WithDeadline(engCtx, deadline)
		}
		stop := context.AfterFunc(ctx, cancel)
		conn, err := out.DialContext(dctx, network, M.ParseSocksaddrHostPort(host, uint16(p)))
		if err != nil {
			stop()
			cancel()
			return nil, err
		}
		return &managedConn{Conn: conn, done: func() { stop(); cancel() }}, nil
	}
}

// dnsConfig translates validated DNS policy into frontend transports and fallback behavior.
func (d *Daemon) dnsConfig(cfg model.DNS) dnsfront.Config {
	c := dnsfront.Config{Listen: cfg.Listen, Timeout: 5 * time.Second, Bootstrap: cfg.Bootstrap, RequireBootstrap: cfg.Route != "", Route: cfg.Route, Log: d.log}
	for _, raw := range cfg.Upstreams {
		u, _ := model.ParseUpstream(raw)
		c.Upstreams = append(c.Upstreams, u)
	}
	if cfg.Route == "" {
		c.Fallback = cfg.Fallback
	}
	if cfg.Route == "connection" {
		c.DialContext = d.dnsDial(cfg.Connection)
		c.Route = "connection:" + cfg.Connection
		c.DirectFallback = cfg.Failure == "direct"
	}
	return c
}

// recordDNSRoute updates counters and journals transitions into or out of direct fallback.
func (d *Daemon) recordDNSRoute(route string) {
	d.featureMu.Lock()
	prev := d.dnsInfo.Route
	d.dnsInfo.Route = route
	d.dnsInfo.Checked = time.Now()
	if route == "direct-fallback" {
		d.dnsInfo.Fallbacks++
	}
	d.featureMu.Unlock()
	if prev != route && route == "direct-fallback" {
		d.audit("dns", "Direct DNS fallback", "dns", "warn", "DNS tunnel did not respond: requests went directly to the encrypted resolver")
	}
	if prev == "direct-fallback" && route != prev {
		d.audit("dns", "Restore selected DNS route", "dns", "ok", route)
	}
}

// recordDNSBlock counts and journals a blocked client DNS request.
func (d *Daemon) recordDNSBlock(name, client, source string) {
	d.featureMu.Lock()
	d.dnsInfo.Blocked++
	d.featureMu.Unlock()
	d.journals[journal.Routes].Add(journal.Entry{Host: name, Client: client, Network: "dns", Outbound: "block", Source: source, Rule: "DNS: " + source})
}
