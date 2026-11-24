package stats

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

type staticGroup struct {
	adapter.OutboundGroup
	tag     string
	members []string
}

func (g staticGroup) Tag() string   { return g.tag }
func (g staticGroup) Type() string  { return "selector" }
func (g staticGroup) All() []string { return g.members }

type staticOutboundManager struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
}

func (m staticOutboundManager) Outbounds() []adapter.Outbound {
	list := make([]adapter.Outbound, 0, len(m.byTag))
	for _, out := range m.byTag {
		list = append(list, out)
	}
	return list
}

func (m staticOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	out, ok := m.byTag[tag]
	return out, ok
}

func TestTargetClassesStopOnCyclesAndStillFindLeaves(t *testing.T) {
	manager := staticOutboundManager{byTag: map[string]adapter.Outbound{
		"direct": fakeOut{tag: "direct", kind: "direct"},
		"vpn":    fakeOut{tag: "vpn", kind: "vless"},
		"block":  fakeOut{tag: "block", kind: "block"},
		"a":      staticGroup{tag: "a", members: []string{"b", "direct"}},
		"b":      staticGroup{tag: "b", members: []string{"a", "vpn"}},
		"c":      staticGroup{tag: "c", members: []string{"c", "direct", "block"}},
		"d":      staticGroup{tag: "d", members: []string{"d"}},
	}}
	ctx := service.ContextWithDefaultRegistry(t.Context())
	RegisterTargetClasses(ctx, manager)
	for tag, want := range map[string]TargetClass{"a": TargetMixed, "b": TargetMixed, "c": TargetDirect, "d": TargetUnknown} {
		if got := TargetClassOf(ctx, manager.byTag[tag]); got != want {
			t.Errorf("target %s has class %v, want %v", tag, got, want)
		}
	}
}
