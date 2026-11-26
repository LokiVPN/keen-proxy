package stats

import (
	"context"
	"iter"
	"slices"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// TargetClass describes a target's forwarding leaves or a blocking-only path.
type TargetClass uint8

const (
	TargetUnknown TargetClass = 0
	TargetDirect  TargetClass = 1
	TargetVPN     TargetClass = 2
	TargetMixed               = TargetDirect | TargetVPN
	TargetBlock   TargetClass = 4
)

type targetClasses map[string]TargetClass

// RegisterTargetClasses records each group's static class before the router
// starts. The map belongs to this core's context and is read-only during use.
func RegisterTargetClasses(ctx context.Context, manager adapter.OutboundManager) {
	classes := make(targetClasses)
	for _, out := range manager.Outbounds() {
		if _, group := targetMembers(out); group {
			classes[out.Tag()] = walkTargetLeaves(manager, out.Tag())
		}
	}
	service.MustRegister(ctx, classes)
}

// TargetClassOf uses the core's configured members for groups. Leaf types can
// be classified directly, including endpoints outside the outbound list.
func TargetClassOf(ctx context.Context, out adapter.Outbound) TargetClass {
	if out == nil {
		return TargetUnknown
	}
	if _, group := targetMembers(out); group {
		return service.FromContext[targetClasses](ctx)[out.Tag()]
	}
	return leafTargetClass(out.Type())
}

func targetMembers(out adapter.Outbound) ([]string, bool) {
	if group, ok := out.(adapter.OutboundGroup); ok {
		return group.All(), true
	}
	if out.Type() == model.SubscriptionBalanceOutboundType {
		return out.Dependencies(), true
	}
	return nil, false
}

// TrafficMemberTags resolves a group's possible accounting tags. The router
// attributes traffic to a per-connection group when it picks a member at dial time.
func TrafficMemberTags(manager adapter.OutboundManager, tag string) ([]string, bool) {
	out, ok := manager.Outbound(tag)
	if !ok {
		return nil, false
	}
	if _, group := trafficMembers(out); !group {
		return nil, false
	}
	var tags []string
	for leaf := range targetLeaves(manager, tag, trafficMembers) {
		tags = append(tags, leaf.Tag())
	}
	slices.Sort(tags)
	return tags, true
}

// SelectedTCPLeaf follows declared group members to one concrete outbound.
// It records any configured reserve edge in the selected path.
func SelectedTCPLeaf(manager adapter.OutboundManager, tag string, isReserve func(group, member string) bool) (leaf adapter.Outbound, reserve bool) {
	selected := func(out adapter.Outbound) ([]string, bool) {
		members, group := targetMembers(out)
		if !group {
			return nil, false
		}
		if selector, ok := out.(adapter.OutboundGroup); ok {
			if next := selector.Selected(N.NetworkTCP); next != nil && slices.Contains(members, next.Tag()) {
				reserve = reserve || isReserve(out.Tag(), next.Tag())
				return []string{next.Tag()}, true
			}
		}
		return nil, true
	}
	for out := range targetLeaves(manager, tag, selected) {
		return out, reserve
	}
	return nil, reserve
}

// HasAlternativeTargetLeaf uses the static group graph to distinguish a
// group with choices from a group that aliases a single outbound.
func HasAlternativeTargetLeaf(manager adapter.OutboundManager, root, selected string) bool {
	for leaf := range targetLeaves(manager, root, targetMembers) {
		if leaf.Tag() != selected {
			return true
		}
	}
	return false
}

func trafficMembers(out adapter.Outbound) ([]string, bool) {
	// Match the sing-box-lx router's outbound chain cut.
	if _, selectsAtDial := out.(interface{ SelectsPerConnectionLx() }); selectsAtDial {
		return nil, false
	}
	return targetMembers(out)
}

// Block leaves determine the class only if there are no forwarding leaves.
func walkTargetLeaves(manager adapter.OutboundManager, root string) TargetClass {
	class := TargetUnknown
	for leaf := range targetLeaves(manager, root, targetMembers) {
		class |= leafTargetClass(leaf.Type())
		if class&TargetMixed == TargetMixed {
			break
		}
	}
	if forwarding := class & TargetMixed; forwarding != TargetUnknown {
		return forwarding
	}
	return class
}

func targetLeaves(manager adapter.OutboundManager, root string, membersOf func(adapter.Outbound) ([]string, bool)) iter.Seq[adapter.Outbound] {
	return func(yield func(adapter.Outbound) bool) {
		pending := []string{root}
		seen := make(map[string]bool)
		for len(pending) > 0 {
			last := len(pending) - 1
			tag := pending[last]
			pending = pending[:last]
			if seen[tag] {
				continue
			}
			seen[tag] = true
			out, ok := manager.Outbound(tag)
			if !ok {
				continue
			}
			if members, group := membersOf(out); group {
				pending = append(pending, members...)
			} else if !yield(out) {
				return
			}
		}
	}
}

func leafTargetClass(kind string) TargetClass {
	switch kind {
	case C.TypeDirect:
		return TargetDirect
	case C.TypeBlock:
		return TargetBlock
	case C.TypeDNS:
		return TargetUnknown
	default:
		return TargetVPN
	}
}
