package subscription

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const (
	// maxRoutingJSON bounds the decoded profile; the encoded form is refused
	// before decoding when it could only decode to more than this.
	maxRoutingJSON    = 256 << 10
	maxRoutingEncoded = (maxRoutingJSON + 2) / 3 * 4
	maxRoutingURL     = 2048
	maxRoutingName    = 128
	defaultRouteOrder = "block-direct-proxy"
	routingLinkPrefix = "happ://routing/"
	routingOffLink    = routingLinkPrefix + "off"
	routingMalformed  = "The provider routing profile could not be read"
)

// RoutingProfile is the provider's Happ routing profile. Lists keep the
// provider's raw entries (for example "geosite:youtube" or "domain:x.example")
// in order; interpreting them is left to the consumer. The profile is private
// provider data and is never serialized into public results.
type RoutingProfile struct {
	Name           string
	GlobalProxy    bool   // Happ default is true when the provider does not say.
	RouteOrder     string // Permutation of block, direct and proxy joined by "-".
	DomainStrategy string // AsIs, IPIfNonMatch, IPOnDemand or empty.
	// GeositeURL and GeoipURL are absolute https URLs, or empty when missing or unsafe.
	GeositeURL, GeoipURL string

	DirectSites, DirectIP []string
	ProxySites, ProxyIP   []string
	BlockSites, BlockIP   []string
	// CategoryDisplay stores redacted spellings for categories whose raw
	// references are still needed to extract or reuse provider data.
	CategoryDisplay map[string]string `json:"category_display,omitempty"`
}

// rawRoutingProfile mirrors the Happ JSON. encoding/json matches field names
// case-insensitively, which the real "Geositeurl" spelling relies on.
type rawRoutingProfile struct {
	Name           string
	GlobalProxy    json.RawMessage
	RouteOrder     string
	DomainStrategy string
	Geositeurl     string
	Geoipurl       string
	DirectSites    []string
	DirectIp       []string
	ProxySites     []string
	ProxyIp        []string
	BlockSites     []string
	BlockIp        []string
}

var errRoutingLink = errors.New(routingMalformed)

// ParseRoutingLink reads a happ://routing/add/<base64 JSON> or
// happ://routing/onadd/<base64 JSON> link. "happ://routing/off" means the
// provider sends no rules and returns (nil, nil). Errors are fixed messages
// that never include provider text.
func ParseRoutingLink(value string) (*RoutingProfile, error) {
	return parseRoutingLink(value, displayRedactor{})
}

func parseRoutingLink(value string, sensitive displayRedactor) (*RoutingProfile, error) {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, routingOffLink) {
		return nil, nil
	}
	if len(value) < len(routingLinkPrefix) || !strings.EqualFold(value[:len(routingLinkPrefix)], routingLinkPrefix) {
		return nil, errRoutingLink
	}
	verb, encoded, _ := strings.Cut(value[len(routingLinkPrefix):], "/")
	if verb = strings.ToLower(verb); verb != "add" && verb != "onadd" {
		return nil, errRoutingLink
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" || len(encoded) > maxRoutingEncoded {
		return nil, errRoutingLink
	}
	decoded, ok := decodeBase64Text(encoded)
	if !ok || len(decoded) > maxRoutingJSON {
		return nil, errRoutingLink
	}
	var raw rawRoutingProfile
	if err := json.Unmarshal([]byte(decoded), &raw); err != nil {
		return nil, errRoutingLink
	}
	profile := &RoutingProfile{
		Name:           providerText(raw.Name, maxRoutingName, sensitive),
		GlobalProxy:    routingGlobalProxy(raw.GlobalProxy),
		RouteOrder:     routingOrder(raw.RouteOrder),
		DomainStrategy: routingStrategy(raw.DomainStrategy),
		GeositeURL:     routingDatURL(raw.Geositeurl),
		GeoipURL:       routingDatURL(raw.Geoipurl),
		DirectSites:    routingEntries(raw.DirectSites),
		DirectIP:       routingEntries(raw.DirectIp),
		ProxySites:     routingEntries(raw.ProxySites),
		ProxyIP:        routingEntries(raw.ProxyIp),
		BlockSites:     routingEntries(raw.BlockSites),
		BlockIP:        routingEntries(raw.BlockIp),
	}
	for _, list := range [][]string{profile.DirectSites, profile.DirectIP, profile.ProxySites, profile.ProxyIP, profile.BlockSites, profile.BlockIP} {
		for _, entry := range list {
			profile.rememberCategoryDisplay(entry, displayRoutingCategory(entry, sensitive))
		}
	}
	return profile, nil
}

// RestoreCategoryDisplay keeps the fetch-time redaction and adds protection
// for raw category references in snapshots created before it was recorded.
func (p *RoutingProfile) RestoreCategoryDisplay(entry, display string) string {
	if p == nil {
		return display
	}
	if saved := p.CategoryDisplay[entry]; saved != "" {
		return saved
	}
	p.rememberCategoryDisplay(entry, display)
	return display
}

func (p *RoutingProfile) rememberCategoryDisplay(entry, display string) {
	if display != entry {
		if p.CategoryDisplay == nil {
			p.CategoryDisplay = make(map[string]string)
		}
		p.CategoryDisplay[entry] = display
	}
}

func displayRoutingCategory(entry string, sensitive displayRedactor) string {
	prefix, category, _ := strings.Cut(entry, ":")
	if prefix != "geosite" && prefix != "geoip" {
		return entry
	}
	// Form control values must not contain line breaks. Keep the prefix for
	// localized category labels and for geosite/geoip availability reasons.
	category = strings.ReplaceAll(strings.ReplaceAll(category, "\n", " "), "\t", " ")
	display := displayText(category, 256, sensitive)
	if display == "" && category != "" {
		display = redactedDisplay
	}
	return prefix + ":" + display
}

// routingGlobalProxy accepts a JSON boolean or the strings "true" and "false";
// anything else keeps Happ's default of true.
func routingGlobalProxy(value json.RawMessage) bool {
	var decoded any
	if json.Unmarshal(value, &decoded) != nil {
		return true
	}
	switch v := decoded.(type) {
	case bool:
		return v
	case string:
		return !strings.EqualFold(strings.TrimSpace(v), "false")
	}
	return true
}

func routingOrder(value string) string {
	parts := strings.Split(value, "-")
	slices.Sort(parts)
	if strings.Join(parts, "-") != "block-direct-proxy" {
		return defaultRouteOrder
	}
	return value
}

func routingStrategy(value string) string {
	switch value {
	case "AsIs", "IPIfNonMatch", "IPOnDemand":
		return value
	}
	return ""
}

func routingDatURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxRoutingURL {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || httpsOrigin(u) == "" {
		return ""
	}
	return u.String()
}

func routingEntries(values []string) []string {
	var entries []string
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			entries = append(entries, value)
		}
	}
	return entries
}

// resolveRouting applies the delivery rules: a non-empty routing header alone
// decides, otherwise the body link is used. A routing-enable value other than
// true or 1 withholds the provider rules without an error. The returned error
// text is fixed and empty when nothing is wrong.
func resolveRouting(headers, comments http.Header, bodyLink string, sensitive displayRedactor) (*RoutingProfile, string) {
	if enable := strings.TrimSpace(firstValue(headers, comments, "routing-enable")); enable != "" && enable != "1" && !strings.EqualFold(enable, "true") {
		return nil, ""
	}
	link := strings.TrimSpace(headers.Get("routing"))
	if link == "" {
		link = bodyLink
	}
	if link == "" {
		return nil, ""
	}
	profile, err := parseRoutingLink(link, sensitive)
	if err != nil {
		return nil, routingMalformed
	}
	return profile, ""
}

// firstValue returns the first non-empty header value, else the body comment.
func firstValue(headers, comments http.Header, name string) string {
	for _, value := range headers.Values(name) {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return comments.Get(name)
}

// isRoutingLine reports whether a body line carries a Happ routing link, which
// is provider configuration and not a node.
func isRoutingLine(line string) bool {
	return len(line) >= len(routingLinkPrefix) && strings.EqualFold(line[:len(routingLinkPrefix)], routingLinkPrefix)
}
