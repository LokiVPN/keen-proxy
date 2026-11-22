package compile

import (
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
}

// SubscriptionBalance identifies one compiled per-connection policy and its shared node outbounds.
type SubscriptionBalance struct {
	SourceID   string
	Tag        string
	Strategy   string
	Candidates []string
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
				SourceID: source, Tag: target, Strategy: nodeID, Candidates: slices.Compact(candidates),
			})
		case len(candidates) == 0:
			result.block = true
			tags[target] = model.TargetBlock
		case nodeID == "auto":
			result.block = true
			result.selectors = append(result.selectors, SubscriptionSelector{SourceID: source, Tag: target, Candidates: candidates})
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

// managedSelector emits stable engine bytes when the provider only reorders nodes.
// Block is the safe initial selection until the daemon restores or picks a node.
func managedSelector(selector SubscriptionSelector) obj {
	members := slices.Clone(selector.Candidates)
	slices.Sort(members)
	return obj{
		"type": "selector", "tag": selector.Tag,
		"outbounds": append([]string{model.TargetBlock}, members...), "default": model.TargetBlock,
		"interrupt_exist_connections": true,
	}
}
