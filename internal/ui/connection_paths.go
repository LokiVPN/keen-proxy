package ui

import (
	"net/url"
	"strings"
)

func connectionDetailPath(id string) string {
	return "/connections/id/" + connectionIDSegment(id)
}

// connectionIDSegment keeps arbitrary legacy IDs in one URL segment. Browsers
// normalize both literal and percent-escaped dot segments, so mark those and
// escape the marker itself when it already starts an ID.
func connectionIDSegment(id string) string {
	if id == "." || id == ".." || strings.HasPrefix(id, "~") {
		id = "~" + id
	}
	return url.PathEscape(id)
}

// connectionIDFromSegment removes the marker after URL unescaping, including
// from http.Request.PathValue, which already returns the unescaped segment.
func connectionIDFromSegment(segment string) string {
	return strings.TrimPrefix(segment, "~")
}

func connectionEnabledField(id string) string {
	// Use the same lossless representation for IDs in native form submissions.
	return "enabled." + connectionIDSegment(id)
}
