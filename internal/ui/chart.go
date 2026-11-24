package ui

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/stats"
)

const (
	chartWindow = 30 * time.Minute
	chartWidth  = 668
	chartHeight = 122
)

type chartData struct {
	Label          string
	Times          [4]string
	Mid, Top       float64
	RX, TX         string
	RXArea, TXArea string
}

// Chart renders rates in Mbit/s over the 30 minutes ending at now, with labels
// in now's timezone. Series comes in timestamp order from the traffic tracker.
func Chart(series []stats.Point, now time.Time, label string) template.HTML {
	start := now.Add(-chartWindow)
	first, end := start.UnixMilli(), now.UnixMilli()
	peak := 0.0
	for _, point := range series {
		if point.T >= first && point.T <= end {
			peak = max(peak, megabits(point.Down), megabits(point.Up))
		}
	}
	tick := max(1, math.Ceil(peak/2))
	data := chartData{Label: label, Mid: tick, Top: 2 * tick}
	for i := range data.Times {
		data.Times[i] = start.Add(time.Duration(i) * chartWindow / 3).Format("15:04")
	}

	var rx, tx strings.Builder
	var firstX, lastX float64
	for _, point := range series {
		if point.T < first || point.T > end {
			continue
		}
		x := chartWidth * float64(point.T-first) / float64(end-first)
		segment := " L"
		if rx.Len() == 0 {
			firstX, segment = x, "M"
		}
		lastX = x
		fmt.Fprintf(&rx, "%s%.1f %.1f", segment, x, chartHeight*(1-megabits(point.Down)/data.Top))
		fmt.Fprintf(&tx, "%s%.1f %.1f", segment, x, chartHeight*(1-megabits(point.Up)/data.Top))
	}
	if rx.Len() != 0 {
		data.RX, data.TX = rx.String(), tx.String()
		baseline := fmt.Sprintf(" L%.1f %d L%.1f %d Z", lastX, chartHeight, firstX, chartHeight)
		data.RXArea, data.TXArea = data.RX+baseline, data.TX+baseline
	}

	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, "chart", data); err != nil {
		return ""
	}
	return template.HTML(buf.String()) // All values were escaped by the chart template.
}

func megabits(rate float64) float64 {
	if rate > 0 && !math.IsInf(rate, 0) {
		return rate / 1e6
	}
	return 0
}
