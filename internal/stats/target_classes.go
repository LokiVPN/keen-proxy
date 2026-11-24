package stats

import (
	"context"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
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

// walkTargetLeaves visits each reachable tag once. Block leaves determine the
// class only if the group has no direct or VPN leaves.
func walkTargetLeaves(manager adapter.OutboundManager, root string) TargetClass {
	pending := []string{root}
	seen := make(map[string]bool)
	class := TargetUnknown
	for len(pending) > 0 && class&TargetMixed != TargetMixed {
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
		if members, group := targetMembers(out); group {
			pending = append(pending, members...)
		} else {
			class |= leafTargetClass(out.Type())
		}
	}
	if forwarding := class & TargetMixed; forwarding != TargetUnknown {
		return forwarding
	}
	return class
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
