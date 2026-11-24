package ui

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

const devicesFormSize = 2 << 20

// devicesDraft holds the edited switches and the effective modes originally
// displayed by the form. Discovery changes independently of the revision.
type devicesDraft struct {
	Modes, Displayed    map[string]model.Mode
	Snapshot            string
	Rows                []deviceRow
	NewDevices, Blocked bool
	Bulk                model.Mode
	Skipped             int
}

func (p pages) devicesGet(w http.ResponseWriter, r *http.Request) {
	if role := p.role(r); role != RoleManage && role != RoleView {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	p.renderDevices(w, r, http.StatusOK, p.deps.Config(), nil, "", "")
}

func (p pages) devicesPost(w http.ResponseWriter, r *http.Request) {
	if p.role(r) != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, devicesFormSize)
	if err := r.ParseForm(); err != nil {
		p.renderDevices(w, r, http.StatusBadRequest, p.deps.Config(), nil, "devices_invalid_form", "")
		return
	}
	cfg, message := p.checkRevision(r)
	if message != "" {
		p.renderDevices(w, r, http.StatusConflict, p.deps.Config(), nil, "revision_changed", "")
		return
	}

	home := homeNetwork(cfg)
	draft, ok := p.parseDevicesDraft(r.PostForm)
	if !ok || (home == nil && draft.NewDevices) {
		p.renderDevices(w, r, http.StatusBadRequest, cfg, nil, "devices_invalid_form", "")
		return
	}
	draft.prepareRows(cfg, home, p.deps.Devices())
	if draft.Blocked {
		p.renderDevices(w, r, http.StatusUnprocessableEntity, cfg, &draft, "devices_enable_unavailable", "")
		return
	}
	if draft.Bulk != model.ModeInherit {
		p.renderDevices(w, r, http.StatusOK, cfg, &draft, "", "")
		return
	}

	if home != nil {
		home.Mode = draft.homeMode(home)
	}
	clients := make(map[string]int, len(cfg.Clients))
	for i, client := range cfg.Clients {
		clients[deviceMAC(client.MAC)] = i
	}
	for _, mac := range slices.Sorted(maps.Keys(draft.Modes)) {
		mode := draft.Modes[mac]
		if i, exists := clients[mac]; exists {
			cfg.Clients[i].Mode = mode
		} else {
			cfg.Clients = append(cfg.Clients, model.Client{MAC: mac, Mode: mode})
		}
	}
	p.applyDevices(w, r, cfg, &draft)
}

// prepareRows checks the current address only for an edit to split mode.
// Every submitted row keeps an explicit mode, including bulk skips.
func (d *devicesDraft) prepareRows(cfg *model.Config, home *model.Network, discovered []DiscoveredDevice) {
	byMAC := deviceSnapshot(cfg, home, discovered)
	d.Rows = make([]deviceRow, 0, len(d.Modes))
	for mac, mode := range d.Modes {
		row, found := byMAC[mac]
		if !found {
			row = resolveDevicePolicy(deviceRow{MAC: mac}, cfg.Networks, home)
		}
		displayed := d.Displayed[mac]
		blocked := row.EnableProblem != "" && displayed != model.ModeSplit
		switch {
		case d.Bulk == model.ModeSplit && blocked:
			d.Skipped++
		case d.Bulk != model.ModeInherit:
			mode = d.Bulk
		}
		if mode == model.ModeSplit && blocked {
			mode = displayed
			d.Blocked = d.Bulk == model.ModeInherit
		}
		d.Modes[mac], row.Mode = mode, mode
		d.Rows = append(d.Rows, row)
	}
}

func (d *devicesDraft) homeMode(home *model.Network) model.Mode {
	if !d.NewDevices {
		return model.ModeOff
	}
	if home.Mode == model.ModeFull {
		return model.ModeFull
	}
	return model.ModeSplit
}

func deviceMAC(raw string) string {
	mac, err := net.ParseMAC(raw)
	if err != nil {
		return ""
	}
	return mac.String()
}

// applyDevices validates the draft before asking the daemon to commit it.
// The daemon checks the same revision again under its commit lock.
func (p pages) applyDevices(w http.ResponseWriter, r *http.Request, cfg *model.Config, draft *devicesDraft) {
	revision := r.PostForm.Get("rev")
	validationErr := cfg.Validate()
	err := validationErr
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
		defer cancel()
		err = p.deps.Apply(ctx, cfg, revision)
	}
	if err == nil {
		redirectWithFlash(w, r, "/devices", "flash_saved")
		return
	}
	current := p.deps.Config()
	var unsaved *model.AppliedUnsavedError
	switch {
	case errors.As(err, &unsaved):
		p.renderDevices(w, r, http.StatusInternalServerError, current, nil, "apply_not_saved", "")
	case errors.Is(err, model.ErrConfigChanged), Revision(current) != revision:
		p.renderDevices(w, r, http.StatusConflict, current, nil, "revision_changed", "")
	default:
		detail := ""
		// Changing only modes and adding validated MACs to a valid config
		// can fail policy validation. Existing config or runtime errors
		// may carry unrelated values and are only shown as a fixed message.
		if validationErr != nil && current.Clone().Validate() == nil {
			detail = validationErr.Error()
		}
		p.renderDevices(w, r, http.StatusUnprocessableEntity, current, draft, "devices_apply_error", detail)
	}
}
