package ui

import (
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

type devicesPage struct {
	Revision, Validation, Snapshot string
	Rows                           []deviceRow
	HasHome, NewDevices, Draft     bool
	Skipped                        int
}

type deviceRow struct {
	MAC, Name, EnableProblem string
	IP                       netip.Addr
	Mode                     model.Mode
	clientTarget             string
}

func (p pages) renderDevices(w http.ResponseWriter, r *http.Request, status int, cfg *model.Config, draft *devicesDraft, messageKey, detail string) {
	data := p.opts.pageData(r)
	data.Title = data.Text["nav_devices"]
	data.SignedIn = true
	data.ViewOnly = p.role(r) == RoleView
	data.Flash = takeFlash(w, r, data.Text)
	data.Message = data.Text[messageKey]
	if cfg != nil {
		home := homeNetwork(cfg)
		page := &devicesPage{
			Revision: Revision(cfg), Validation: detail, Draft: draft != nil,
			HasHome: home != nil, NewDevices: home != nil && home.Mode != model.ModeOff,
		}
		if draft != nil {
			page.Rows, page.NewDevices, page.Skipped = draft.Rows, draft.NewDevices, draft.Skipped
			page.Snapshot = draft.Snapshot
		} else {
			page.Rows = slices.Collect(maps.Values(deviceSnapshot(cfg, home, p.deps.Devices())))
			page.Snapshot = p.deviceFormSnapshot(page.Revision, page.Rows)
		}
		slices.SortFunc(page.Rows, compareDevices)
		data.Devices = page
	}
	render(w, r, status, "devices", data)
}

// deviceSnapshot joins cached observations and configured clients by MAC.
func deviceSnapshot(cfg *model.Config, home *model.Network, discovered []DiscoveredDevice) map[string]deviceRow {
	byMAC := make(map[string]deviceRow, len(discovered)+len(cfg.Clients))
	for _, device := range discovered {
		if mac := deviceMAC(device.MAC); mac != "" {
			ip, _ := netip.ParseAddr(device.IP)
			byMAC[mac] = deviceRow{MAC: mac, Name: device.Name, IP: ip}
		}
	}
	for _, client := range cfg.Clients {
		mac := deviceMAC(client.MAC)
		if mac == "" {
			continue
		}
		row := byMAC[mac]
		row.MAC, row.Mode, row.clientTarget = mac, client.Mode, client.Target
		if strings.TrimSpace(client.Name) != "" {
			row.Name = client.Name
		}
		if client.IP != "" {
			row.IP, _ = netip.ParseAddr(client.IP)
		}
		byMAC[mac] = row
	}
	for mac, row := range byMAC {
		byMAC[mac] = resolveDevicePolicy(row, cfg.Networks, home)
	}
	return byMAC
}

func resolveDevicePolicy(row deviceRow, networks []model.Network, home *model.Network) deviceRow {
	network := deviceNetwork(row.IP, networks, home)
	if row.Mode == model.ModeInherit {
		row.Mode = model.ModeOff
		if network != nil {
			row.Mode = network.Mode
		}
	}
	if row.clientTarget == "" && (network == nil || network.Target == "") {
		row.EnableProblem = "devices_no_vpn_target"
		if row.IP.IsValid() && (network == nil || (home != nil && !deviceNetworkContains(home, row.IP))) {
			row.EnableProblem = "devices_outside_home"
		}
	}
	return row
}

// deviceNetwork follows the compiler's first matching CIDR for a known
// address. MAC-only rows use the usual Home policy until an address is known.
func deviceNetwork(ip netip.Addr, networks []model.Network, home *model.Network) *model.Network {
	if !ip.IsValid() {
		return home
	}
	for i := range networks {
		if deviceNetworkContains(&networks[i], ip) {
			return &networks[i]
		}
	}
	return nil
}

func deviceNetworkContains(network *model.Network, ip netip.Addr) bool {
	prefix, err := netip.ParsePrefix(network.CIDR)
	return err == nil && prefix.Contains(ip)
}

func compareDevices(a, b deviceRow) int {
	if a.IP.IsValid() != b.IP.IsValid() {
		// The zero address sorts first by default. Put unidentified IPs last.
		return b.IP.Compare(a.IP)
	}
	if order := a.IP.Compare(b.IP); order != 0 {
		return order
	}
	return strings.Compare(a.MAC, b.MAC)
}
