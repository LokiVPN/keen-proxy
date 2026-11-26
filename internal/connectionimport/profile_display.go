package connectionimport

import (
	"slices"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/links"
	"github.com/ordo-systems/keen-proxy/internal/profiledisplay"
)

// SafeLinkLabel checks a provider-redacted name as well as its original
// spelling, so truncation cannot make a repeated credential look safe.
func SafeLinkLabel(link, redacted string) string {
	if redacted == "" {
		return ""
	}
	profile, err := links.Parse(link)
	if err != nil || profiledisplay.Repeats(profileDisplayStrings(profile), nil, links.Name(link), redacted) {
		return ""
	}
	return redacted
}

func profileDisplayStrings(profile any) []profiledisplay.StringLeaf {
	return profiledisplay.StringLeaves(profile, func(path []string, raw string) bool {
		// A known protocol or transport selector is a literal, even if it
		// happens to have the shape of a Base64 value.
		return (slices.EqualFunc(path, []string{"type"}, strings.EqualFold) && protocolLabel[raw] != "") ||
			(slices.EqualFunc(path, []string{"transport", "type"}, strings.EqualFold) && detailTransportLabels[raw] != "")
	})
}
