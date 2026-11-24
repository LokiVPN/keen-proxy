package daemon

import (
	"cmp"
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/stats"
)

// RoutingStatus describes the active routing plan and the LAN devices it
// covers. Health and Failover hold the most recent connection observations.
type RoutingStatus struct {
	Ready                   bool
	Devices, ManagedDevices int
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
	for _, network := range d.cfg.Networks {
		for _, target := range []string{network.Target, network.Default} {
			if _, _, managed := model.ParseManagedTarget(target); managed {
				status.TargetClasses[target] = d.eng.TargetClass(cmp.Or(d.targetAliases[target], target))
			}
		}
	}
	return status
}

// TrafficSeries returns the daemon-lifetime history window for VPN rates.
func (d *Daemon) TrafficSeries() []stats.Point { return d.stats.TunnelSeries() }
