package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/stats"
)

func TestTrafficChartUsesLocalizedAxisUnits(t *testing.T) {
	const (
		ruBit  = " \u0431\u0438\u0442/\u0441"
		ruKbit = " \u043a\u0431\u0438\u0442/\u0441"
		ruMbit = " \u041c\u0431\u0438\u0442/\u0441"
		ruGbit = " \u0413\u0431\u0438\u0442/\u0441"
	)
	now := time.Date(2026, time.November, 24, 9, 42, 0, 0, time.UTC)
	for _, tt := range []struct {
		name   string
		peak   float64
		en, ru [3]string
	}{
		{"zero", 0, [3]string{"2 bit/s", "1 bit/s", "0 bit/s"}, [3]string{"2" + ruBit, "1" + ruBit, "0" + ruBit}},
		{"kilobits", 40e3, [3]string{"40 kbit/s", "20 kbit/s", "0 kbit/s"}, [3]string{"40" + ruKbit, "20" + ruKbit, "0" + ruKbit}},
		{"megabits", 6e6, [3]string{"10 Mbit/s", "5 Mbit/s", "0 Mbit/s"}, [3]string{"10" + ruMbit, "5" + ruMbit, "0" + ruMbit}},
		{"gigabits", 2e9, [3]string{"2 Gbit/s", "1 Gbit/s", "0 Gbit/s"}, [3]string{"2" + ruGbit, "1" + ruGbit, "0" + ruGbit}},
		{"fractional step", 5e6, [3]string{"5 Mbit/s", "2.5 Mbit/s", "0 Mbit/s"}, [3]string{"5" + ruMbit, "2,5" + ruMbit, "0" + ruMbit}},
	} {
		series := []stats.Point{
			{T: now.Add(-31 * time.Minute).UnixMilli(), Down: 4e9},
			{T: now.Add(-time.Minute).UnixMilli(), Up: tt.peak},
			{T: now.UnixMilli(), Down: tt.peak / 2},
		}
		for _, locale := range []struct {
			lang  string
			ticks [3]string
		}{{"en", tt.en}, {"ru", tt.ru}} {
			t.Run(tt.name+"/"+locale.lang, func(t *testing.T) {
				chart := string(overviewTraffic(series, now, locale.lang).Chart)
				for _, tick := range locale.ticks {
					if !strings.Contains(chart, "<span>"+tick+"</span>") {
						t.Errorf("missing axis tick %q", tick)
					}
				}
			})
		}
	}
}

func TestChartRendersAxesAndTrafficPaths(t *testing.T) {
	now := time.Date(2026, time.November, 24, 9, 42, 0, 0, time.FixedZone("router", 5*60*60))
	empty := string(Chart(nil, now, "en", "VPN traffic"))
	assertContains(t, empty, `class="chart-y"`, `class="chart-x"`, `class="grid"`, ">0 bit/s</span>", ">09:12</span>", ">09:22</span>", ">09:32</span>", ">09:42</span>")
	if strings.Contains(empty, `class="rx-l"`) {
		t.Error("empty chart implies that incoming traffic was measured")
	}

	full := string(Chart([]stats.Point{
		{T: now.Add(-30 * time.Minute).UnixMilli(), Down: 10e6, Up: 4e6},
		{T: now.Add(-10 * time.Minute).UnixMilli(), Down: 40e6, Up: 6e6},
		{T: now.UnixMilli(), Down: 8e6, Up: 2e6},
	}, now, "en", `Traffic for "VPN" <1>`))
	assertContains(t, full, ">40 Mbit/s</span>", ">20 Mbit/s</span>", ">0 Mbit/s</span>", ">09:12</span>", ">09:42</span>",
		`preserveAspectRatio="none"`, `vector-effect="non-scaling-stroke"`,
		`class="rx-a"`, `class="tx-a"`, `class="rx-l"`, `class="tx-l"`,
		"M0.0 91.5 L445.3 0.0 L668.0 97.6", "Traffic for &#34;VPN&#34; &lt;1&gt;")
}

func TestChartShowsOneSampleInWindow(t *testing.T) {
	now := time.Date(2026, time.November, 24, 9, 42, 0, 0, time.UTC)
	rendered := string(Chart([]stats.Point{
		{T: now.Add(-31 * time.Minute).UnixMilli(), Down: 100e6},
		{T: now.Add(-15 * time.Minute).UnixMilli(), Down: 15e6, Up: 5e6},
	}, now, "en", "VPN traffic"))
	assertContains(t, rendered,
		`<circle class="rx-point" cx="334" cy="30.5" r="3"/>`,
		`<circle class="tx-point" cx="334" cy="91.5" r="3"/>`)
	if strings.Contains(rendered, `class="rx-l"`) {
		t.Error("a single sample produced an incoming rate line")
	}
}
