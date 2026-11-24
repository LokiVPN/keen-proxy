package main

import (
	"reflect"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

func TestRoutingRulesProjection(t *testing.T) {
	rules := compile.BuildProviderRules(&subscription.RoutingProfile{
		RouteOrder: "block-direct-proxy", GlobalProxy: true,
		DirectSites: []string{"domain:a.example", "full:b.example", "literal", "regexp:^c"},
		DirectIP:    []string{"geoip:private", "192.0.2.0/24"},
		ProxySites:  []string{"geosite:youtube"},
	}, nil, nil, nil)
	deps := uiDeps{daemon: routingSnapshotDaemon{rules: rules}}
	got := deps.ProviderRules()
	want := ui.RoutingRules{
		Source: "fixture", State: "partial", HasProfile: true, GlobalProxy: true,
		Rules: []ui.RoutingRule{
			{Key: "direct:literals:site", Action: "direct", Kind: "site", Source: "literals", LiteralCount: 4},
			{Key: "direct:literals:ip", Action: "direct", Kind: "ip", Source: "literals", LiteralCount: 1},
			{Key: "proxy:geosite:youtube", Action: "proxy", Kind: "site", Source: "geosite:youtube", Unavailable: "provider sent no geosite file"},
		},
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("routing projection = %+v, want %+v", got, want)
	}
}

type routingSnapshotDaemon struct {
	managementDaemon
	rules compile.ProviderRules
}

func (d routingSnapshotDaemon) ProviderRules() (compile.ProviderRules, *model.ProviderRulesSettings, daemon.ProviderRulesState) {
	return d.rules, &model.ProviderRulesSettings{Source: "fixture"}, daemon.ProviderRulesPartial
}
