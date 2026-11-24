package daemon

import (
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/stats"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// RoutingStatus describes the active routing plan and the LAN devices it
// covers. Health and Failover hold the most recent connection observations.
type RoutingStatus struct {
	Ready                   bool
	Devices, ManagedDevices int
	Health                  map[string]ConnHealth
	Failover                map[string]FailoverInfo
	DirectTargets           map[string]bool
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
		if slices.Contains(d.plan.Excluded, addr) {
			continue
		}
		for _, source := range d.plan.Sources {
			if source.Contains(addr) {
				status.ManagedDevices++
				break
			}
		}
	}
	status.DirectTargets = make(map[string]bool)
	for _, conn := range d.cfg.Connections {
		if out, _, ok := d.eng.Outbound(conn.ID); ok {
			tcp := stats.ResolveForNetwork(out, N.NetworkTCP)
			udp := stats.ResolveForNetwork(out, N.NetworkUDP)
			if tcp != nil && udp != nil && tcp.Type() == C.TypeDirect && udp.Type() == C.TypeDirect {
				status.DirectTargets[conn.ID] = true
			}
		}
	}
	return status
}

// TrafficSeries returns the daemon-lifetime history window for VPN rates.
func (d *Daemon) TrafficSeries() []stats.Point { return d.stats.TunnelSeries() }
