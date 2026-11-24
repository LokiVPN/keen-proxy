package main

import (
	"net/http"

	"github.com/ordo-systems/keen-proxy/internal/api"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

// uiDeps adapts the daemon's applied snapshot to the page layer.
type uiDeps struct {
	daemon interface{ Config() *model.Config }
}

func (d uiDeps) Config() *model.Config {
	return d.daemon.Config()
}

func pageRole(r *http.Request) ui.Role {
	switch api.RoleFrom(r.Context()) {
	case api.RoleView:
		return ui.RoleView
	case api.RoleManage:
		return ui.RoleManage
	default:
		return ui.RoleDeny
	}
}
