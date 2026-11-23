package compile

import (
	"cmp"
	"errors"
	"maps"
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// SubscriptionSelector links one used automatic target to its provider-ordered nodes.
type SubscriptionSelector struct {
	SourceID   string
	Tag        string
	Candidates []string
	// Fallback is the resolved reserve tag, empty when none is configured.
	Fallback string
}

// SubscriptionBalance identifies one compiled per-connection policy and its shared node outbounds.
type SubscriptionBalance struct {
	SourceID   string
	Tag        string
	Strategy   string
	Candidates []string
	Fallback   string
}

type subscriptionRouting struct {
	outbounds []obj
	selectors []SubscriptionSelector
	balances  []SubscriptionBalance
	nodeTags  []string
	block     bool
}

// subscriptionTargets finds configured references even when their snapshots are absent.
func subscriptionTargets(c *model.Config) []string {
	if len(c.Subscriptions) == 0 {
		return nil
	}
	targets := map[string]bool{}
	add := func(target string) {
		if c.HasManagedTarget(target) {
			targets[target] = true
		}
	}
	for _, group := range c.Groups {
		add(group.Target)
	}
	for _, network := range c.Networks {
		add(network.Target)
		add(network.Default)
	}
	for _, client := range c.Clients {
		add(client.Target)
	}
	return slices.Sorted(maps.Keys(targets))
}

// compileSubscriptions translates managed references without giving a provider
// control of firewall bypasses or the user's persisted connection list.
func compileSubscriptions(in Input, tags map[string]string) (subscriptionRouting, error) {
	var result subscriptionRouting
	nodes := map[string]subscription.Node{}
	for _, target := range subscriptionTargets(in.Config) {
		source, nodeID, _ := model.ParseManagedTarget(target)
		balance := model.IsSubscriptionBalance(nodeID)
		reserve := subscriptionReserve(in.Config, source, tags)
		var candidates []string
		for _, node := range in.Subscriptions[source] {
			if balance || nodeID == "auto" || nodeID == node.ID {
				tag := model.ManagedTarget(source, node.ID)
				nodes[tag] = node
				candidates = append(candidates, tag)
			}
		}
		switch {
		case balance:
			result.block = true
			slices.Sort(candidates)
			result.balances = append(result.balances, SubscriptionBalance{
				SourceID: source, Tag: target, Strategy: nodeID, Candidates: slices.Compact(candidates), Fallback: reserve,
			})
		case len(candidates) == 0:
			result.block = true
			tags[target] = cmp.Or(reserve, model.TargetBlock)
		case nodeID == "auto":
			result.block = true
			result.selectors = append(result.selectors, SubscriptionSelector{SourceID: source, Tag: target, Candidates: candidates, Fallback: reserve})
		}
	}
	if len(nodes) == 0 {
		return result, nil
	}
	result.nodeTags = slices.Sorted(maps.Keys(nodes))
	var profiles model.Config
	for _, tag := range result.nodeTags {
		profiles.Connections = append(profiles.Connections, model.Connection{ID: tag, Type: model.ConnLink, Link: nodes[tag].Link})
	}
	parsed, err := connections(&profiles)
	if err != nil {
		return result, errors.New("invalid subscription node")
	}
	result.outbounds = parsed.outbounds
	return result, nil
}

// subscriptionReserve resolves a source's configured reserve to an outbound
// tag; a connection with a failover chain resolves through its selector.
func subscriptionReserve(c *model.Config, sourceID string, tags map[string]string) string {
	for _, source := range c.Subscriptions {
		if source.ID == sourceID && source.Fallback != "" {
			return cmp.Or(tags[source.Fallback], source.Fallback)
		}
	}
	return ""
}

// managedSelector emits stable engine bytes when the provider only reorders nodes.
// Block is the safe initial selection until the daemon restores or picks a node.
func managedSelector(selector SubscriptionSelector) obj {
	members := slices.Clone(selector.Candidates)
	slices.Sort(members)
	outbounds := append([]string{model.TargetBlock}, members...)
	if selector.Fallback != "" && selector.Fallback != model.TargetBlock {
		outbounds = append(outbounds, selector.Fallback)
	}
	return obj{
		"type": "selector", "tag": selector.Tag,
		"outbounds": outbounds, "default": model.TargetBlock,
		"interrupt_exist_connections": true,
	}
}
