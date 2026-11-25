package connectionimport

import (
	"errors"
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

var ErrRoutingOverride = errors.New("profile includes unsupported routing options")

// ValidateRoutingOptions restricts imported dial policy to explicitly
// configured manual detours. Route actions and host bindings belong to the
// router configuration, not to an imported connection.
func ValidateRoutingOptions(c model.Connection, cfg *model.Config) error {
	manualTarget := func(target string) bool {
		return target != model.TargetDirect && target != model.TargetBlock &&
			slices.ContainsFunc(cfg.Connections, func(saved model.Connection) bool { return saved.ID == target })
	}
	if hasRoutingOverride(c.Outbound, manualTarget) || hasRoutingOverride(c.Endpoint, manualTarget) {
		return ErrRoutingOverride
	}
	return nil
}

func hasRoutingOverride(value any, manualTarget func(string) bool) bool {
	switch options := value.(type) {
	case map[string]any:
		for key, option := range options {
			switch normalizedProfileKey(key) {
			case "headers":
				continue // HTTP header names are data rather than settings.
			case "detour":
				if target, ok := option.(string); ok && target != "" && !manualTarget(target) {
					return true
				}
			case "bindinterface", "inet4bindaddress", "inet6bindaddress", "bindaddressnoport", "protectpath",
				"routingmark", "netns", "networkstrategy", "networktype", "fallbacknetworktype":
				if option != nil && option != "" && option != false && option != float64(0) {
					return true
				}
			default:
				if hasRoutingOverride(option, manualTarget) {
					return true
				}
			}
		}
	case []any:
		return slices.ContainsFunc(options, func(item any) bool { return hasRoutingOverride(item, manualTarget) })
	}
	return false
}
