package ui

import "github.com/ordo-systems/keen-proxy/internal/model"

// Deps provides the applied configuration snapshot used to verify form revisions.
type Deps interface {
	Config() *model.Config
}
