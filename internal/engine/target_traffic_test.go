package engine

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/sagernet/sing-box/adapter"
)

func TestTunnelChartUsesRoutedTargetLeaves(t *testing.T) {
	tracker := stats.NewTracker()
	engine := Engine{Tracker: tracker}
	if _, err := engine.Apply([]byte(`{
		"log":{"disabled":true},
		"outbounds":[
			{"type":"direct","tag":"local-egress"},
			{"type":"socks","tag":"vpn","server":"127.0.0.1","server_port":1},
			{"type":"selector","tag":"direct-group","outbounds":["local-egress"]},
			{"type":"urltest","tag":"mixed-group","mode":"round_robin","outbounds":["local-egress","vpn"],"url":"http://127.0.0.1:1/generate_204"},
			{"type":"selector","tag":"vpn-group","outbounds":["vpn"]}
		]
	}`)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	for _, flow := range []struct {
		target, resolved string
		upload           int
	}{
		{"direct-group", "local-egress", 100},
		{"mixed-group", "", 200}, // The router leaves the balancing group to choose during the dial.
		{"mixed-group", "local-egress", 400},
		{"vpn-group", "vpn", 800},
	} {
		outbound, ctx, ok := engine.Outbound(flow.target)
		if !ok {
			t.Fatalf("missing test outbound %q", flow.target)
		}
		chain := []adapter.Outbound{outbound}
		if flow.resolved != "" {
			member, _, ok := engine.Outbound(flow.resolved)
			if !ok {
				t.Fatalf("missing test member %q", flow.resolved)
			}
			chain = append(chain, member)
		}
		device, inbound := net.Pipe()
		tracked := tracker.RoutedConnection(ctx, inbound, adapter.InboundContext{Domain: "fixture.example", Network: "tcp",
			RouteOutbound: flow.target, OutboundChain: chain}, nil, outbound)
		go func() {
			defer device.Close()
			_, _ = device.Write(make([]byte, flow.upload))
		}()
		n, err := io.Copy(io.Discard, tracked)
		_ = tracked.Close()
		if err != nil || n != int64(flow.upload) {
			t.Fatalf("recorded %d out of %d fixture bytes, err %v", n, flow.upload, err)
		}
	}
	go tracker.Run(t.Context())
	deadline := time.Now().Add(2 * stats.SampleInterval)
	for time.Now().Before(deadline) {
		if points := tracker.TunnelSeries(); len(points) > 0 {
			want := float64(200+400+800) * 8 / stats.SampleInterval.Seconds()
			if points[0].Up != want {
				t.Fatalf("VPN chart upload = %g, want %g for both mixed flows and the tunnel flow", points[0].Up, want)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the tracker did not sample the fixture traffic")
}
