package engine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/publicsuffix"
)

type subscriptionBalanceOptions struct {
	Outbounds []string `json:"outbounds"`
	// Fallback replaces block as the target while no member is eligible.
	Fallback string `json:"fallback,omitempty"`
}

func registerSubscriptionBalance(registry *outbound.Registry) {
	outbound.Register[subscriptionBalanceOptions](registry, model.SubscriptionBalanceOutboundType, newSubscriptionBalance)
}

// subscriptionBalance picks one concrete outbound for each connection. Pool
// updates publish a complete, immutable snapshot without changing live streams.
type subscriptionBalance struct {
	outbound.Adapter
	strategy    string
	fallback    string
	manager     adapter.OutboundManager
	connections adapter.ConnectionManager
	block       adapter.Outbound
	candidates  []adapter.Outbound
	pool        atomic.Pointer[subscriptionBalancePool]

	roundRobinMu   sync.Mutex
	nextRoundRobin int
}

type subscriptionBalancePool struct {
	tcp, udp []subscriptionBalanceMember
	sessions *subscriptionBalanceSessions
}

type subscriptionBalanceMember struct {
	outbound adapter.Outbound
	order    int // index in the stable, complete candidate list
}

func newSubscriptionBalance(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, opts subscriptionBalanceOptions) (adapter.Outbound, error) {
	source, strategy, ok := model.ParseManagedTarget(tag)
	if !ok || !model.IsSubscriptionBalance(strategy) {
		return nil, fmt.Errorf("invalid subscription balance tag %q", tag)
	}
	for _, candidate := range opts.Outbounds {
		id, node, ok := model.ParseManagedTarget(candidate)
		if !ok || id != source || node == "auto" || model.IsSubscriptionBalance(node) {
			return nil, fmt.Errorf("invalid subscription balance member %q", candidate)
		}
	}
	members := slices.Clone(opts.Outbounds)
	slices.Sort(members)
	dependencies := []string{model.TargetBlock}
	if opts.Fallback != "" && opts.Fallback != model.TargetBlock {
		dependencies = append(dependencies, opts.Fallback)
	}
	dependencies = append(dependencies, slices.Compact(members)...)
	return &subscriptionBalance{
		Adapter:     outbound.NewAdapter(model.SubscriptionBalanceOutboundType, tag, []string{N.NetworkTCP, N.NetworkUDP}, dependencies),
		strategy:    strategy,
		fallback:    opts.Fallback,
		manager:     service.FromContext[adapter.OutboundManager](ctx),
		connections: service.FromContext[adapter.ConnectionManager](ctx),
	}, nil
}

// Start resolves the compiled dependencies once their outbounds have started.
func (b *subscriptionBalance) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	for _, tag := range b.Dependencies() {
		member, ok := b.manager.Outbound(tag)
		if !ok {
			return fmt.Errorf("subscription balance outbound %q is missing", tag)
		}
		switch {
		case tag == model.TargetBlock:
			if member.Type() != "block" {
				return fmt.Errorf("subscription balance requires a block outbound")
			}
			if b.fallback == "" || b.fallback == model.TargetBlock {
				b.block = member
			}
		case tag == b.fallback:
			b.block = member
		default:
			b.candidates = append(b.candidates, member)
		}
	}
	return nil
}

// updatePool is serialized by Engine and intersects health with the compiled
// candidates and each transport's capabilities.
func (b *subscriptionBalance) updatePool(healthy []string, sessions *subscriptionBalanceSessions) {
	pool := &subscriptionBalancePool{sessions: sessions}
	eligible := make(map[string]struct{}, len(healthy))
	for _, tag := range healthy {
		eligible[tag] = struct{}{}
	}
	for i, candidate := range b.candidates {
		if _, ok := eligible[candidate.Tag()]; !ok {
			continue
		}
		member := subscriptionBalanceMember{outbound: candidate, order: i}
		networks := candidate.Network()
		if slices.Contains(networks, N.NetworkTCP) {
			pool.tcp = append(pool.tcp, member)
		}
		if slices.Contains(networks, N.NetworkUDP) {
			pool.udp = append(pool.udp, member)
		}
	}
	b.pool.Store(pool)
}

func (b *subscriptionBalance) selectMember(network string, metadata *adapter.InboundContext) adapter.Outbound {
	pool := b.pool.Load()
	if pool == nil {
		return b.block
	}
	var members, alternate []subscriptionBalanceMember
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		members, alternate = pool.tcp, pool.udp
	case N.NetworkUDP:
		members, alternate = pool.udp, pool.tcp
	}
	if len(members) == 0 {
		return b.block
	}
	switch b.strategy {
	case model.SubscriptionConsistentHash:
		return balanceMemberForSite(subscriptionBalanceSite(metadata), members)
	case model.SubscriptionStickySession:
		key := subscriptionBalanceSessionKey{client: metadata.Source.Addr.Unmap(), site: subscriptionBalanceSite(metadata)}
		return pool.sessions.selectMember(key, members, alternate)
	default: // round robin
		return b.roundRobinMember(members)
	}
}

// roundRobinMember advances across the stable candidate order, skipping any
// member that cannot serve this connection's transport.
func (b *subscriptionBalance) roundRobinMember(members []subscriptionBalanceMember) adapter.Outbound {
	b.roundRobinMu.Lock()
	defer b.roundRobinMu.Unlock()
	chosen := members[0]
	for _, member := range members {
		if member.order >= b.nextRoundRobin {
			chosen = member
			break
		}
	}
	b.nextRoundRobin = chosen.order + 1
	return chosen.outbound
}

func subscriptionBalanceSite(metadata *adapter.InboundContext) string {
	host := metadata.Domain
	if host == "" {
		host = metadata.Destination.Fqdn
	}
	if host == "" {
		return metadata.Destination.Addr.Unmap().String()
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	if site, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return site
	}
	return host
}

// balanceMemberForSite uses rendezvous hashing. A surviving winner remains the
// winner after another member is removed, independent of provider ordering.
func balanceMemberForSite(site string, members []subscriptionBalanceMember) adapter.Outbound {
	var highest uint64
	var chosen adapter.Outbound
	for _, member := range members {
		digest := sha256.Sum256([]byte(site + "\x00" + member.outbound.Tag()))
		score := binary.BigEndian.Uint64(digest[:8])
		if chosen == nil || score > highest {
			highest, chosen = score, member.outbound
		}
	}
	return chosen
}

func (b *subscriptionBalance) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	metadata := subscriptionBalanceDialMetadata(ctx, destination)
	return b.selectMember(network, &metadata).DialContext(ctx, network, destination)
}

func (b *subscriptionBalance) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	metadata := subscriptionBalanceDialMetadata(ctx, destination)
	return b.selectMember(N.NetworkUDP, &metadata).ListenPacket(ctx, destination)
}

func subscriptionBalanceDialMetadata(ctx context.Context, destination M.Socksaddr) adapter.InboundContext {
	metadata := adapter.InboundContext{Destination: destination}
	if inbound := adapter.ContextFrom(ctx); inbound != nil {
		metadata.Domain, metadata.Source = inbound.Domain, inbound.Source
	}
	return metadata
}
