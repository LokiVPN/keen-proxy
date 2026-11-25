package connectionimport

import (
	"errors"
	"slices"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

var ErrRoutingOverride = errors.New("profile includes unsupported routing options")

// ValidateRoutingOptions allows references only to objects retained by the
// import. A single profile has no such targets: wrapper settings are discarded
// and its own tag becomes the KeenProxy connection ID.
func ValidateRoutingOptions(c model.Connection) error {
	if hasRoutingOverride(c.Outbound) || hasRoutingOverride(c.Endpoint) {
		return ErrRoutingOverride
	}
	return nil
}

func hasRoutingOverride(value any) bool {
	switch options := value.(type) {
	case map[string]any:
		for key, option := range options {
			key = normalizedRoutingKey(key)
			if key == "headers" {
				continue // The keys of an HTTP header map are header names.
			}
			if hasTagReference(key, option) || hasHostRoutingOverride(key, option) || hasRoutingOverride(option) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(options, hasRoutingOverride)
	}
	return false
}

var routingKeySeparators = strings.NewReplacer("-", "", "_", "")

func normalizedRoutingKey(key string) string {
	return strings.ToLower(routingKeySeparators.Replace(key))
}

func hasTagReference(key string, value any) bool {
	if strings.HasSuffix(key, "resolver") || strings.HasSuffix(key, "dialer") || key == "dial" || key == "httpclient" {
		if options, ok := value.(map[string]any); ok {
			// A resolver object names a DNS tag in server. A dial option can
			// embed options or refer to a tag; its nested detour is visited
			// independently.
			referenceKey := "tag"
			if strings.HasSuffix(key, "resolver") {
				referenceKey = "server"
			}
			for field, option := range options {
				if normalizedRoutingKey(field) == referenceKey && hasTagValue(option) {
					return true
				}
			}
		}
		return hasTagValue(value)
	}
	return (strings.HasSuffix(key, "detour") || key == "outbound" || key == "outbounds") && hasTagValue(value)
}

func hasTagValue(value any) bool {
	switch v := value.(type) {
	case string:
		return v != ""
	case []any:
		return slices.ContainsFunc(v, hasTagValue)
	}
	return false
}

func hasHostRoutingOverride(key string, value any) bool {
	switch key {
	case "bindinterface", "inet4bindaddress", "inet6bindaddress", "bindaddressnoport", "protectpath",
		"routingmark", "netns", "networkstrategy", "networktype", "fallbacknetworktype":
		return value != nil && value != "" && value != false && value != float64(0)
	}
	return false
}
