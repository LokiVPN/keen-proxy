package engine

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

// subscriptionBalanceTracker records the concrete member at route time, then
// passes that same choice to the connection handler for forwarding.
type subscriptionBalanceTracker struct {
	next adapter.ConnectionTracker
}

type subscriptionBalanceConn struct {
	net.Conn
	member adapter.Outbound
}

type subscriptionBalancePacketConn struct {
	N.PacketConn
	member adapter.Outbound
}

func (c *subscriptionBalancePacketConn) Upstream() any { return c.PacketConn }

func matchedSubscriptionBalance(metadata *adapter.InboundContext) (*subscriptionBalance, bool) {
	if len(metadata.OutboundChain) == 0 {
		return nil, false
	}
	balance, ok := metadata.OutboundChain[len(metadata.OutboundChain)-1].(*subscriptionBalance)
	return balance, ok
}

func (t subscriptionBalanceTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, rule adapter.Rule, outbound adapter.Outbound) net.Conn {
	if balance, ok := matchedSubscriptionBalance(&metadata); ok {
		member := balance.selectMember(N.NetworkTCP, &metadata)
		if t.next != nil {
			metadata.OutboundChain = append(metadata.OutboundChain, member)
			conn = t.next.RoutedConnection(ctx, conn, metadata, rule, member)
		}
		return &subscriptionBalanceConn{Conn: conn, member: member}
	}
	if t.next != nil {
		return t.next.RoutedConnection(ctx, conn, metadata, rule, outbound)
	}
	return conn
}

func (t subscriptionBalanceTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, rule adapter.Rule, outbound adapter.Outbound) N.PacketConn {
	if balance, ok := matchedSubscriptionBalance(&metadata); ok {
		member := balance.selectMember(N.NetworkUDP, &metadata)
		if t.next != nil {
			metadata.OutboundChain = append(metadata.OutboundChain, member)
			conn = t.next.RoutedPacketConnection(ctx, conn, metadata, rule, member)
		}
		return &subscriptionBalancePacketConn{PacketConn: conn, member: member}
	}
	if t.next != nil {
		return t.next.RoutedPacketConnection(ctx, conn, metadata, rule, outbound)
	}
	return conn
}

func (t subscriptionBalanceTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, rule adapter.Rule, outbound adapter.Outbound) tun.FlowTracker {
	if t.next == nil {
		return nil
	}
	return t.next.RoutedFlow(ctx, metadata, rule, outbound)
}

func (b *subscriptionBalance) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var member adapter.Outbound
	if selected, ok := conn.(*subscriptionBalanceConn); ok {
		member, conn = selected.member, selected.Conn
	} else {
		member = b.selectMember(N.NetworkTCP, &metadata)
	}
	metadata.OutboundChain = append(metadata.OutboundChain, member)
	if handler, ok := member.(adapter.ConnectionHandler); ok {
		handler.NewConnection(ctx, conn, metadata, onClose)
		return
	}
	b.connections.NewConnection(ctx, member, conn, metadata, onClose)
}

func (b *subscriptionBalance) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var member adapter.Outbound
	// The router can add a NAT wrapper after tracking. Keep it around the
	// accounted packets while recovering the original member choice.
	if selected, ok := common.Cast[*subscriptionBalancePacketConn](conn); ok {
		member = selected.member
		if conn == selected {
			conn = selected.PacketConn
		}
	} else {
		member = b.selectMember(N.NetworkUDP, &metadata)
	}
	metadata.OutboundChain = append(metadata.OutboundChain, member)
	if handler, ok := member.(adapter.PacketConnectionHandler); ok {
		handler.NewPacketConnection(ctx, conn, metadata, onClose)
		return
	}
	b.connections.NewPacketConnection(ctx, member, conn, metadata, onClose)
}
