package model

import (
	"regexp"
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	SubscriptionRoundRobin     = "round-robin"
	SubscriptionConsistentHash = "consistent-hash"
	SubscriptionStickySession  = "sticky-session"

	// SubscriptionBalanceOutboundType identifies the generated sing-box outbound.
	SubscriptionBalanceOutboundType = "subscription-balance"
)

var (
	managedTargetPattern = regexp.MustCompile(`^subscription:([a-z0-9_-]{1,64}):([a-z0-9-]{1,32})$`)
	managedNodeIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// IsSubscriptionBalance reports whether a managed target selects a node for each new connection.
func IsSubscriptionBalance(mode string) bool {
	switch mode {
	case SubscriptionRoundRobin, SubscriptionConsistentHash, SubscriptionStickySession:
		return true
	default:
		return false
	}
}

// ManagedTarget names a pinned node or a node selection policy of a subscription.
func ManagedTarget(sourceID, nodeID string) string {
	return "subscription:" + sourceID + ":" + nodeID
}

// ParseManagedTarget recognizes the persisted target format without consulting runtime snapshots.
func ParseManagedTarget(target string) (sourceID, nodeID string, ok bool) {
	match := managedTargetPattern.FindStringSubmatch(target)
	if match == nil || (match[2] != "auto" && !IsSubscriptionBalance(match[2]) && !managedNodeIDPattern.MatchString(match[2])) {
		return "", "", false
	}
	return match[1], match[2], true
}

// HasManagedTarget accepts references to declared sources even when a pinned node is unavailable.
func (c *Config) HasManagedTarget(target string) bool {
	id, _, ok := ParseManagedTarget(target)
	return ok && slices.ContainsFunc(c.Subscriptions, func(source subscription.Source) bool {
		return source.ID == id
	})
}

func (c *Config) validateSubscriptions(add func(string, ...any)) {
	seen := make(map[string]bool, len(c.Subscriptions))
	for i, source := range c.Subscriptions {
		if err := subscription.ValidateSource(source); err != nil {
			add("subscriptions[%d]: %v", i, err)
		} else if seen[source.ID] {
			add("subscriptions[%d]: duplicate id %q", i, source.ID)
		}
		seen[source.ID] = true
	}
}

// validateSubscriptionFallbacks runs once connection IDs are known. A reserve
// is a manual connection or a built-in target, never another subscription.
func (c *Config) validateSubscriptionFallbacks(conns map[string]bool, add func(string, ...any)) {
	for i, source := range c.Subscriptions {
		switch fb := source.Fallback; {
		case fb == "" || fb == TargetDirect || fb == TargetBlock || conns[fb]:
		case c.HasManagedTarget(fb):
			add("subscriptions[%d]: fallback cannot be a subscription target", i)
		default:
			add("subscriptions[%d]: unknown fallback %q", i, fb)
		}
	}
}
