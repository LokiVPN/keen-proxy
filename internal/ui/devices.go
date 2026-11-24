package ui

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

const devicesFormSize = 2 << 20

// devicesDraft holds the modes of the exact rows submitted with the form.
// Discovery can change without changing the applied config revision.
type devicesDraft struct {
	Modes      map[string]model.Mode
	NewDevices bool
	Bulk       model.Mode
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
	clients := make(map[string]int, len(cfg.Clients))
	for i, client := range cfg.Clients {
		clients[deviceMAC(client.MAC)] = i
	}
	draft, ok := parseDevicesDraft(r.PostForm, cfg.Clients, clients)
	if !ok || (home == nil && draft.NewDevices) {
		p.renderDevices(w, r, http.StatusBadRequest, cfg, nil, "devices_invalid_form", "")
		return
	}
	if draft.Bulk != model.ModeInherit {
		for mac := range draft.Modes {
			draft.Modes[mac] = draft.Bulk
		}
		p.renderDevices(w, r, http.StatusOK, cfg, &draft, "", "")
		return
	}

	if home != nil {
		switch {
		case !draft.NewDevices:
			home.Mode = model.ModeOff
		case home.Mode != model.ModeFull:
			home.Mode = model.ModeSplit
		}
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

// parseDevicesDraft treats unchecked rows as off and permits full mode only
// for an existing full-tunnel client whose switch was left unchanged.
func parseDevicesDraft(form url.Values, clients []model.Client, indices map[string]int) (devicesDraft, bool) {
	newDevices, bulk := form["new"], form["bulk"]
	if len(newDevices) > 1 || (len(newDevices) == 1 && newDevices[0] != "1") || len(bulk) > 1 {
		return devicesDraft{}, false
	}
	draft := devicesDraft{
		Modes: make(map[string]model.Mode, len(form["device"])), NewDevices: len(newDevices) == 1,
	}
	if len(bulk) == 1 {
		draft.Bulk = model.Mode(bulk[0])
		if draft.Bulk != model.ModeSplit && draft.Bulk != model.ModeOff {
			return devicesDraft{}, false
		}
	}
	for _, raw := range form["device"] {
		mac := deviceMAC(raw)
		if _, exists := draft.Modes[mac]; mac == "" || exists {
			return devicesDraft{}, false
		}
		draft.Modes[mac] = model.ModeOff
	}
	for _, mode := range []model.Mode{model.ModeSplit, model.ModeFull} {
		for _, raw := range form[string(mode)] {
			mac := deviceMAC(raw)
			if draft.Modes[mac] != model.ModeOff {
				return devicesDraft{}, false
			}
			if mode == model.ModeFull {
				if i, exists := indices[mac]; !exists || clients[i].Mode != model.ModeFull {
					return devicesDraft{}, false
				}
			}
			draft.Modes[mac] = mode
		}
	}
	return draft, true
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
