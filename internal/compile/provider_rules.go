package compile

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ordo-systems/keen-proxy/internal/geodata"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// ProviderRule is one switchable rule of a provider's routing profile: one
// geosite:/geoip: category entry, or all literal entries of one list. An
// unavailable rule keeps its key with empty lists and a fixed English reason.
// Built rules are shared read-only values.
type ProviderRule struct {
	Key         string   `json:"key"`    // <action>:<entry>, or <action>:literals:<kind>
	Action      string   `json:"action"` // proxy, direct or block
	Kind        string   `json:"kind"`   // site (a Sites list) or ip (an Ip list)
	Source      string   `json:"source"` // the entry as written, or "literals"
	Label       string   `json:"label"`  // English display name
	Unavailable string   `json:"unavailable,omitempty"`
	Suffix      []string `json:"suffix,omitempty"`
	Full        []string `json:"full,omitempty"`
	Keyword     []string `json:"keyword,omitempty"`
	Regex       []string `json:"regex,omitempty"`
	CIDR        []string `json:"cidr,omitempty"` // canonical masked prefixes
}

// ProviderRules is a provider's Happ routing profile interpreted for routing.
type ProviderRules struct {
	Name        string         `json:"name,omitempty"`
	RouteOrder  string         `json:"route_order"`
	GlobalProxy bool           `json:"global_proxy"`
	Rules       []ProviderRule `json:"rules,omitempty"` // domain and IP rules in profile list order
	// Unsupported holds entries KeenProxy cannot apply, as written: at most
	// maxUnsupported entries of at most maxUnsupportedBytes each.
	Unsupported []string `json:"unsupported,omitempty"`
}

const (
	providerProxy  = "proxy"
	providerDirect = "direct"
	providerBlock  = "block"
	providerSite   = "site"
	providerIP     = "ip"

	maxUnsupported      = 50
	maxUnsupportedBytes = 128
)

// Fixed reasons of unavailable category rules.
const (
	providerMissing   = "not in the provider's data"
	providerNoGeosite = "provider sent no geosite file"
	providerNoGeoip   = "provider sent no geoip file"
	providerNotLoaded = "provider data not loaded"
	providerNoCountry = "not in the built-in country data"
)

var providerLiteralLabels = map[string]string{
	providerSite: "Other sites from the subscription",
	providerIP:   "Other addresses from the subscription",
}

// providerLabels names common categories; any other category shows its name.
var providerLabels = map[string]string{
	"apple":            "Apple",
	"category-ads":     "Ads",
	"category-ads-all": "Ads (full list)",
	"category-ru":      "Russian sites",
	"discord":          "Discord",
	"epicgames":        "Epic Games",
	"escapefromtarkov": "Escape from Tarkov",
	"facebook":         "Facebook",
	"faceit":           "FACEIT",
	"github":           "GitHub",
	"google":           "Google",
	"google-play":      "Google Play",
	"instagram":        "Instagram",
	"microsoft":        "Microsoft",
	"netflix":          "Netflix",
	"openai":           "OpenAI",
	"pinterest":        "Pinterest",
	"riot":             "Riot Games",
	"spotify":          "Spotify",
	"steam":            "Steam",
	"telegram":         "Telegram",
	"torrent":          "Torrent sites",
	"twitch":           "Twitch",
	"twitch-ads":       "Twitch ads",
	"twitter":          "Twitter",
	"whitelist":        "Whitelisted services",
	"win-spy":          "Windows telemetry",
	"youtube":          "YouTube",
}

// BuildProviderRules interprets a provider's routing profile. sites and ips
// hold the extracted geosite and geoip data keyed by reference as written
// (ProviderRuleRefs); a nil map means that file's data was not loaded, and the
// caller may replace the generic reason of the affected rules with its own.
// countries resolves an uppercase ISO code to built-in prefixes; it is used
// only for two-letter geoip tags of a profile without a geoip file and may be
// nil. private entries are skipped: private addresses are always direct. The
// result depends only on the inputs and shares their slices.
func BuildProviderRules(p *subscription.RoutingProfile, sites map[string]geodata.Sites, ips map[string][]netip.Prefix, countries func(code string) ([]netip.Prefix, bool)) ProviderRules {
	if p == nil {
		return ProviderRules{}
	}
	b := providerBuilder{
		profile: p, sites: sites, ips: ips, countries: countries,
		out:   ProviderRules{Name: p.Name, RouteOrder: p.RouteOrder, GlobalProxy: p.GlobalProxy},
		index: map[string]int{}, unsupported: map[string]bool{},
	}
	for _, list := range providerLists(p) {
		for _, entry := range list.entries {
			b.add(list.action, list.kind, entry)
		}
	}
	return b.out
}

// ProviderRuleRefs returns the geosite references and geoip tags that the
// profile's category entries use, as geodata extraction expects them.
func ProviderRuleRefs(p *subscription.RoutingProfile) (sites, ips map[string]bool) {
	sites, ips = map[string]bool{}, map[string]bool{}
	if p == nil {
		return sites, ips
	}
	for _, list := range providerLists(p) {
		refs := sites
		if list.kind == providerIP {
			refs = ips
		}
		for _, entry := range list.entries {
			if class, ref := parseProviderEntry(list.kind, entry); class == entryCategory {
				refs[ref] = true
			}
		}
	}
	return sites, ips
}

type providerList struct {
	action, kind string
	entries      []string
}

func providerLists(p *subscription.RoutingProfile) []providerList {
	return []providerList{
		{providerDirect, providerSite, p.DirectSites}, {providerDirect, providerIP, p.DirectIP},
		{providerProxy, providerSite, p.ProxySites}, {providerProxy, providerIP, p.ProxyIP},
		{providerBlock, providerSite, p.BlockSites}, {providerBlock, providerIP, p.BlockIP},
	}
}

type entryClass int

const (
	entryUnsupported entryClass = iota
	entryPrivate
	entryCategory // value is a geosite reference or a geoip tag
	entrySuffix
	entryFull
	entryKeyword
	entryRegex
	entryCIDR
)

// parseProviderEntry reads an entry with Xray's syntax for its list: Sites
// lists use the domain syntax, where plain text is a keyword, and Ip lists the
// ip syntax. value is the category reference or the literal to match.
func parseProviderEntry(kind, entry string) (entryClass, string) {
	if kind == providerIP {
		if tag, ok := strings.CutPrefix(entry, "geoip:"); ok {
			return providerCategory(tag, tag)
		}
		if prefix, ok := literalPrefix(entry); ok {
			return entryCIDR, prefix
		}
		return entryUnsupported, ""
	}
	prefix, value, ok := strings.Cut(entry, ":")
	if !ok {
		return entryKeyword, entry
	}
	switch prefix {
	case "geosite":
		name, _, _ := strings.Cut(value, "@")
		return providerCategory(name, value)
	case "domain":
		return providerLiteral(entrySuffix, strings.ToLower(value))
	case "full":
		return providerLiteral(entryFull, strings.ToLower(value))
	case "keyword":
		return providerLiteral(entryKeyword, value)
	case "regexp":
		if _, err := regexp.Compile(value); err != nil {
			return entryUnsupported, ""
		}
		return providerLiteral(entryRegex, value)
	case "ext", "ext-domain", "dotless", "geoip":
		return entryUnsupported, ""
	}
	return entryKeyword, entry // plain text containing a colon
}

func providerCategory(name, ref string) (entryClass, string) {
	switch {
	case name == "" || strings.HasPrefix(name, "!"):
		return entryUnsupported, ""
	case strings.EqualFold(name, "private"):
		return entryPrivate, ""
	}
	return entryCategory, ref
}

func providerLiteral(class entryClass, value string) (entryClass, string) {
	if value == "" {
		return entryUnsupported, ""
	}
	return class, value
}

// literalPrefix returns an IP or CIDR literal as a canonical masked prefix.
func literalPrefix(value string) (string, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked().String(), true
	}
	if addr, err := netip.ParseAddr(value); err == nil && addr.Zone() == "" {
		return netip.PrefixFrom(addr, addr.BitLen()).String(), true
	}
	return "", false
}

type providerBuilder struct {
	profile     *subscription.RoutingProfile
	sites       map[string]geodata.Sites
	ips         map[string][]netip.Prefix
	countries   func(string) ([]netip.Prefix, bool)
	out         ProviderRules
	index       map[string]int // rule key to its position in out.Rules
	unsupported map[string]bool
}

func (b *providerBuilder) add(action, kind, entry string) {
	class, value := parseProviderEntry(kind, entry)
	switch class {
	case entryPrivate:
		return
	case entryUnsupported:
		b.addUnsupported(entry)
		return
	case entryCategory:
		key := action + ":" + entry
		if _, merged := b.index[key]; !merged {
			b.index[key] = len(b.out.Rules)
			b.out.Rules = append(b.out.Rules, b.category(key, action, kind, entry, value))
		}
		return
	}
	key := action + ":literals:" + kind
	i, ok := b.index[key]
	if !ok {
		i = len(b.out.Rules)
		b.index[key] = i
		b.out.Rules = append(b.out.Rules, ProviderRule{Key: key, Action: action, Kind: kind, Source: "literals", Label: providerLiteralLabels[kind]})
	}
	r := &b.out.Rules[i]
	switch class {
	case entrySuffix:
		r.Suffix = append(r.Suffix, value)
	case entryFull:
		r.Full = append(r.Full, value)
	case entryKeyword:
		r.Keyword = append(r.Keyword, value)
	case entryRegex:
		r.Regex = append(r.Regex, value)
	case entryCIDR:
		r.CIDR = append(r.CIDR, value)
	}
}

func (b *providerBuilder) category(key, action, kind, entry, ref string) ProviderRule {
	r := ProviderRule{Key: key, Action: action, Kind: kind, Source: entry, Label: providerLabel(ref)}
	if kind == providerSite {
		var data geodata.Sites
		data, r.Unavailable = b.domains(ref)
		r.Suffix, r.Full, r.Keyword, r.Regex = data.Suffix, data.Full, data.Keyword, data.Regex
		return r
	}
	var prefixes []netip.Prefix
	prefixes, r.Unavailable = b.prefixes(ref)
	if len(prefixes) > 0 {
		r.CIDR = make([]string, len(prefixes))
		for i, prefix := range prefixes {
			r.CIDR[i] = prefix.Masked().String()
		}
	}
	return r
}

// domains returns a geosite reference's data or the reason it has none. A
// category without domains is treated as absent: an empty rule matches nothing.
func (b *providerBuilder) domains(ref string) (geodata.Sites, string) {
	data, found := b.sites[ref]
	switch {
	case b.profile.GeositeURL == "":
		return geodata.Sites{}, providerNoGeosite
	case b.sites == nil:
		return geodata.Sites{}, providerNotLoaded
	case !found || len(data.Suffix)+len(data.Full)+len(data.Keyword)+len(data.Regex) == 0:
		return geodata.Sites{}, providerMissing
	}
	return data, ""
}

// prefixes resolves a geoip tag from the provider's file or, for a profile
// without one, a two-letter tag from the built-in country data.
func (b *providerBuilder) prefixes(tag string) ([]netip.Prefix, string) {
	if b.profile.GeoipURL == "" {
		if !countryCode(tag) {
			return nil, providerNoGeoip
		}
		var prefixes []netip.Prefix
		known := false
		if b.countries != nil {
			prefixes, known = b.countries(strings.ToUpper(tag))
		}
		if !known || len(prefixes) == 0 {
			return nil, providerNoCountry
		}
		return prefixes, ""
	}
	if b.ips == nil {
		return nil, providerNotLoaded
	}
	if prefixes := b.ips[tag]; len(prefixes) > 0 {
		return prefixes, ""
	}
	return nil, providerMissing
}

func countryCode(tag string) bool {
	if len(tag) != 2 {
		return false
	}
	for i := range len(tag) {
		if c := tag[i] | 0x20; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func providerLabel(ref string) string {
	if label, ok := providerLabels[strings.ToLower(ref)]; ok {
		return label
	}
	return ref
}

// addUnsupported records an entry for display, bounded in count and size.
func (b *providerBuilder) addUnsupported(entry string) {
	if len(b.out.Unsupported) == maxUnsupported {
		return
	}
	if len(entry) > maxUnsupportedBytes {
		n := maxUnsupportedBytes
		for n > 0 && !utf8.RuneStart(entry[n]) {
			n--
		}
		entry = entry[:n]
	}
	if !b.unsupported[entry] {
		b.unsupported[entry] = true
		b.out.Unsupported = append(b.out.Unsupported, entry)
	}
}
