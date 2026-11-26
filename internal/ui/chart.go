package ui

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"strconv"
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
	Ticks          [3]string
	RX, TX         string
	RXArea, TXArea string
	Sample         *chartPoint
}

// chartPoint locates both traffic rates from a single sample in the SVG.
type chartPoint struct{ X, RX, TX float64 }

// Chart renders rates over the 30 minutes ending at now with a localized scale
// and times in now's timezone. Series comes in timestamp order from the tracker.
func Chart(series []stats.Point, now time.Time, lang, label string) template.HTML {
	start := now.Add(-chartWindow)
	first, end := start.UnixMilli(), now.UnixMilli()
	peak := 0.0
	var samples int
	for _, point := range series {
		if point.T >= first && point.T <= end {
			peak = max(peak, validTrafficRate(point.Down), validTrafficRate(point.Up))
			samples++
		}
	}
	scale, unitKey := chartRateUnit(peak)
	unit := translations[lang][unitKey]
	// The plot has two equal intervals. Round up so the upper tick covers the peak.
	tick := niceChartStep(max(1/scale, peak/scale/2))
	top := 2 * tick
	data := chartData{Label: label}
	for i, value := range [...]float64{top, tick, 0} {
		data.Ticks[i] = formatTrafficNumber(value, -1, lang) + " " + unit
	}
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
		yRX := chartHeight * (1 - validTrafficRate(point.Down)/scale/top)
		yTX := chartHeight * (1 - validTrafficRate(point.Up)/scale/top)
		if samples == 1 {
			data.Sample = &chartPoint{X: x, RX: yRX, TX: yTX}
			break
		}
		segment := " L"
		if rx.Len() == 0 {
			firstX, segment = x, "M"
		}
		lastX = x
		fmt.Fprintf(&rx, "%s%.1f %.1f", segment, x, yRX)
		fmt.Fprintf(&tx, "%s%.1f %.1f", segment, x, yTX)
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

func chartRateUnit(peak float64) (scale float64, key string) {
	switch {
	case peak >= 1e9:
		return 1e9, "chart_unit_gbit"
	case peak >= 1e6:
		return 1e6, "chart_unit_mbit"
	case peak >= 1e3:
		return 1e3, "chart_unit_kbit"
	default:
		return 1, "chart_unit_bit"
	}
}

// niceChartStep rounds a positive interval up to the next readable decimal step.
func niceChartStep(minimum float64) float64 {
	magnitude := math.Pow10(int(math.Floor(math.Log10(minimum))))
	for _, multiplier := range [...]float64{1, 2, 2.5, 5} {
		if step := multiplier * magnitude; step >= minimum {
			return step
		}
	}
	return 10 * magnitude
}

func formatTrafficNumber(value float64, decimals int, lang string) string {
	number := strconv.FormatFloat(value, 'f', decimals, 64)
	if lang == "ru" {
		return strings.Replace(number, ".", ",", 1)
	}
	return number
}

func validTrafficRate(rate float64) float64 {
	if rate > 0 && !math.IsInf(rate, 0) {
		return rate
	}
	return 0
}
