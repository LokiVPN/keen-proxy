package ui

import (
	"cmp"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// subscriptionTitles holds the protected titles for configured subscription IDs.
// Apply the localized fallback at render time, including when comparing titles.
type subscriptionTitles map[string]string

// When cfg is nil, the applied observations are also the source inventory.
func subscriptionTitlesFor(cfg *model.Config, subs []AppliedSubscription) subscriptionTitles {
	titles := make(subscriptionTitles, len(subs))
	if cfg != nil {
		for _, source := range cfg.Subscriptions {
			titles[source.ID] = ""
		}
	}
	for _, sub := range subs {
		if _, configured := titles[sub.ID]; cfg == nil || configured {
			titles[sub.ID] = sub.Metadata.Title
		}
	}
	return titles
}

func (titles subscriptionTitles) title(id string, text map[string]string) string {
	return cmp.Or(strings.Join(strings.Fields(titles[id]), " "), text["overview_subscription"])
}

func (titles subscriptionTitles) duplicate(id string, text map[string]string) bool {
	if _, configured := titles[id]; !configured {
		return false
	}
	title := titles.title(id, text)
	for other := range titles {
		if other != id && titles.title(other, text) == title {
			return true
		}
	}
	return false
}

func (titles subscriptionTitles) label(id string, text map[string]string) string {
	title := titles.title(id, text)
	if titles.duplicate(id, text) {
		return title + " · " + id
	}
	return title
}
