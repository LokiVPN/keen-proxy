package subscription

import (
	"slices"
	"strings"
)

// RoutingSummary describes the delivered profile before evaluating its rules.
// It contains no geodata URLs, literal entries or match expressions.
type RoutingSummary struct {
	Name                 string
	GlobalProxy          bool
	Direct, Proxy, Block RoutingActionSummary
}

// RoutingActionSummary describes the site and IP lists for one action.
type RoutingActionSummary struct {
	Sites, IP RoutingListSummary
}

// RoutingListSummary counts all list entries and shows a bounded set of
// distinct category labels. More indicates that some labels were omitted.
type RoutingListSummary struct {
	Count      int
	Categories []string
	More       bool
}

func summarizeRouting(profile *RoutingProfile, sensitive displayRedactor) *RoutingSummary {
	action := func(sites, ips []string) RoutingActionSummary {
		return RoutingActionSummary{
			Sites: summarizeRoutingList(sites, "geosite:", sensitive),
			IP:    summarizeRoutingList(ips, "geoip:", sensitive),
		}
	}
	return &RoutingSummary{
		Name: profile.Name, GlobalProxy: profile.GlobalProxy,
		Direct: action(profile.DirectSites, profile.DirectIP),
		Proxy:  action(profile.ProxySites, profile.ProxyIP),
		Block:  action(profile.BlockSites, profile.BlockIP),
	}
}

func summarizeRoutingList(entries []string, prefix string, sensitive displayRedactor) RoutingListSummary {
	const maxCategories, maxLabel = 8, 64
	summary := RoutingListSummary{Count: len(entries)}
	for _, entry := range entries {
		name, ok := strings.CutPrefix(entry, prefix)
		if !ok {
			continue
		}
		label := displayText(name, maxLabel, sensitive)
		if label == "" || slices.Contains(summary.Categories, label) {
			continue
		}
		if len(summary.Categories) == maxCategories {
			summary.More = true
			break
		}
		summary.Categories = append(summary.Categories, label)
	}
	return summary
}
