package daemon

import (
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/stats"
)

// RoutingStatus describes the active routing plan and the LAN devices it
// covers. Health and Failover hold the most recent connection observations.
type RoutingStatus struct {
	Ready               bool
	Devices, VPNDevices int
	Health              map[string]ConnHealth
	Failover            map[string]FailoverInfo
}

// RoutingStatus reads the daemon state without testing firewall rules or
// probing connections. The plan is installed after the engine and DNS start.
func (d *Daemon) RoutingStatus() RoutingStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	status := RoutingStatus{Ready: d.planOn && !d.planPending, Devices: len(d.neighbors)}
	if d.cfg == nil {
		return status
	}
	status.Failover, status.Health = d.failoverInfoLocked()
	if status.Ready {
		for _, addr := range d.neighbors {
			if slices.Contains(d.plan.Excluded, addr) {
				continue
			}
			for _, source := range d.plan.Sources {
				if source.Contains(addr) {
					status.VPNDevices++
					break
				}
			}
		}
	}
	return status
}

// TrafficSeries returns the daemon-lifetime history window for VPN rates.
func (d *Daemon) TrafficSeries() []stats.Point { return d.stats.TunnelSeries() }
