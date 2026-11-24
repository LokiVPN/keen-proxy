package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/stats"
)

func TestChartRendersAxesAndTrafficPaths(t *testing.T) {
	now := time.Date(2026, time.November, 24, 9, 42, 0, 0, time.FixedZone("router", 5*60*60))
	empty := string(Chart(nil, now, "VPN traffic"))
	assertContains(t, empty, `class="chart-y"`, `class="chart-x"`, `class="grid"`, ">0</span>", ">09:12</span>", ">09:22</span>", ">09:32</span>", ">09:42</span>")
	if strings.Contains(empty, `class="rx-l"`) {
		t.Error("empty chart implies that incoming traffic was measured")
	}

	full := string(Chart([]stats.Point{
		{T: now.Add(-30 * time.Minute).UnixMilli(), Down: 10e6, Up: 4e6},
		{T: now.Add(-10 * time.Minute).UnixMilli(), Down: 40e6, Up: 6e6},
		{T: now.UnixMilli(), Down: 8e6, Up: 2e6},
	}, now, `Traffic for "VPN" <1>`))
	assertContains(t, full, ">40</span>", ">20</span>", ">0</span>", ">09:12</span>", ">09:42</span>",
		`preserveAspectRatio="none"`, `vector-effect="non-scaling-stroke"`,
		`class="rx-a"`, `class="tx-a"`, `class="rx-l"`, `class="tx-l"`,
		"M0.0 91.5 L445.3 0.0 L668.0 97.6", "Traffic for &#34;VPN&#34; &lt;1&gt;")
}
