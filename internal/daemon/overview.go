package daemon

import (
	"cmp"
	"net"
	"net/netip"
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

// RoutingStatus describes the active routing plan and the LAN devices it
// covers. Health and Failover hold the most recent connection observations.
type RoutingStatus struct {
	Ready                   bool
	Devices, ManagedDevices int
	HomeTargets             []string // distinct targets of covered, observed Home clients
	Health                  map[string]ConnHealth
	Failover                map[string]FailoverInfo
	TargetClasses           map[string]stats.TargetClass
	ActiveTargetClasses     map[string]stats.TargetClass // classes of selected failover outbounds
}

// RoutingStatus reads the daemon state without testing firewall rules or
// probing connections. Count devices covered by the running interception plan.
func (d *Daemon) RoutingStatus() RoutingStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	status := RoutingStatus{Devices: len(d.neighbors)}
	if d.cfg == nil {
		return status
	}
	status.Ready = d.planOn && !d.planPending && d.dns != nil && d.eng.Running()
	status.Failover, status.Health = d.failoverInfoLocked()
	if !status.Ready {
		return status
	}
	for _, addr := range d.neighbors {
		if d.routingCoversLocked(addr) {
			status.ManagedDevices++
		}
	}
	status.HomeTargets = d.activeHomeTargetsLocked()
	status.TargetClasses = make(map[string]stats.TargetClass, len(d.cfg.Connections))
	for _, conn := range d.cfg.Connections {
		status.TargetClasses[conn.ID] = d.eng.TargetClass(conn.ID)
	}
	// The compiler routes a connection with a reserve through its selector.
	status.ActiveTargetClasses = make(map[string]stats.TargetClass, len(d.chains))
	for _, chain := range d.chains {
		status.TargetClasses[chain.ID] = d.eng.TargetClass(chain.Tag)
		status.ActiveTargetClasses[chain.ID] = d.eng.TargetClass(status.Failover[chain.ID].Active)
	}
	addManagedTarget := func(target string) {
		if _, _, managed := model.ParseManagedTarget(target); managed {
			status.TargetClasses[target] = d.eng.TargetClass(cmp.Or(d.targetAliases[target], target))
		}
	}
	for _, network := range d.cfg.Networks {
		addManagedTarget(network.Target)
		addManagedTarget(network.Default)
	}
	for _, target := range status.HomeTargets {
		addManagedTarget(target)
	}
	return status
}

func (d *Daemon) routingCoversLocked(addr netip.Addr) bool {
	return !slices.Contains(d.plan.Excluded, addr) && slices.ContainsFunc(d.plan.Sources, func(source netip.Prefix) bool {
		return source.Contains(addr)
	})
}

// activeHomeTargetsLocked finds device overrides whose observed addresses are
// covered by the running plan and belong to Home's first-match policy.
func (d *Daemon) activeHomeTargetsLocked() []string {
	home := d.cfg.HomeNetwork()
	if home == nil || len(d.cfg.Clients) == 0 {
		return nil
	}
	prefix, _ := netip.ParsePrefix(home.CIDR)
	var preceding []netip.Prefix
	for i := range d.cfg.Networks {
		if &d.cfg.Networks[i] == home {
			break
		}
		network, _ := netip.ParsePrefix(d.cfg.Networks[i].CIDR)
		preceding = append(preceding, network)
	}
	var targets []string
	for _, client := range d.cfg.Clients {
		mode := client.Mode
		if mode == model.ModeInherit {
			mode = home.Mode
		}
		if mode != model.ModeFull && mode != model.ModeSplit {
			continue
		}
		mac, err := net.ParseMAC(client.MAC)
		if err != nil {
			continue
		}
		addr := d.neighbors[mac.String()]
		if client.IP != "" {
			static, _ := netip.ParseAddr(client.IP)
			if addr != static {
				continue
			}
		}
		if !prefix.Contains(addr) || slices.ContainsFunc(preceding, func(p netip.Prefix) bool { return p.Contains(addr) }) || !d.routingCoversLocked(addr) {
			continue
		}
		target := cmp.Or(client.Target, home.Target)
		if target == "" && mode == model.ModeSplit && d.cfg.ActiveProviderRules() == nil {
			target = home.Default
		}
		if !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
	}
	return targets
}

// TrafficSeries returns the daemon-lifetime history window for VPN rates.
func (d *Daemon) TrafficSeries() []stats.Point { return d.stats.TunnelSeries() }
