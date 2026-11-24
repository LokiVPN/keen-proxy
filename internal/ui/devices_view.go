package ui

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

type devicesPage struct {
	Revision, Validation       string
	Rows                       []deviceRow
	HasHome, NewDevices, Draft bool
}

type deviceRow struct {
	MAC, Name string
	IP        netip.Addr
	Mode      model.Mode
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
			Rows: deviceRows(cfg, p.deps.Devices(), home, draft),
		}
		if draft != nil {
			page.NewDevices = draft.NewDevices
		}
		data.Devices = page
	}
	render(w, r, status, "devices", data)
}

// deviceRows joins cached observations and configured clients by MAC. A
// submitted draft keeps its row set even when the neighbor cache changes.
func deviceRows(cfg *model.Config, discovered []DiscoveredDevice, home *model.Network, draft *devicesDraft) []deviceRow {
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
		row.MAC, row.Mode = mac, client.Mode
		if strings.TrimSpace(client.Name) != "" {
			row.Name = client.Name
		}
		if client.IP != "" {
			row.IP, _ = netip.ParseAddr(client.IP)
		}
		byMAC[mac] = row
	}
	rows := make([]deviceRow, 0, len(byMAC))
	if draft != nil {
		for mac, mode := range draft.Modes {
			row := byMAC[mac]
			row.MAC, row.Mode = mac, mode
			rows = append(rows, row)
		}
	} else {
		for _, row := range byMAC {
			if row.Mode == model.ModeInherit {
				row.Mode = inheritedDeviceMode(row.IP, cfg.Networks, home)
			}
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, compareDevices)
	return rows
}

// inheritedDeviceMode follows the first matching network for a known IP.
// Without an address, the Home policy supplies the initial switch state.
func inheritedDeviceMode(ip netip.Addr, networks []model.Network, home *model.Network) model.Mode {
	mode := model.ModeOff
	if !ip.IsValid() && home != nil {
		mode = home.Mode
	} else {
		for _, network := range networks {
			prefix, err := netip.ParsePrefix(network.CIDR)
			if err == nil && prefix.Contains(ip) {
				mode = network.Mode
				break
			}
		}
	}
	if mode == model.ModeSplit || mode == model.ModeFull {
		return model.ModeSplit
	}
	return model.ModeOff
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
