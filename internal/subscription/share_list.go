package subscription

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/ordo-systems/keen-proxy/internal/links"
)

const maxNodes = 256

var shareLinkPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

func parseShareList(ctx context.Context, headers http.Header, data []byte, sensitive displayRedactor) Result {
	body := decodeShareListBody(string(data))
	comments := make(http.Header)
	seen := make(map[string]bool)
	var result Result
	var hasContent bool
	var routingLine string
	for line := range strings.Lines(body) {
		if ctx.Err() != nil {
			return withHeaders(headers, sensitive, failure(StateNetworkError, canceledDownload))
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if comment, ok := strings.CutPrefix(line, "#"); ok {
			collectMetadata(comments, comment)
			continue
		}
		if isRoutingLine(line) {
			if routingLine == "" {
				routingLine = line
			}
			continue
		}
		hasContent = true
		if !shareLinkPattern.MatchString(line) {
			continue
		}
		node, ok := parseNode(line, sensitive)
		if !ok {
			result.Skipped++
			continue
		}
		if seen[node.ID] {
			continue
		}
		if len(result.Nodes) == maxNodes {
			return withHeaders(headers, sensitive, failure(StateInvalid, fmt.Sprintf("Subscription response exceeds %d distinct nodes", maxNodes)))
		}
		seen[node.ID] = true
		result.Nodes = append(result.Nodes, node)
	}
	switch {
	case len(result.Nodes) > 0:
		result.State = StateReady
	case hasContent:
		result.State = StateUnsupported
		result.Error = "Subscription response contains no supported profiles"
	default:
		result.State = StateEmpty
		result.Error = "Subscription response contains no profiles"
	}
	result.Metadata = parseMetadata(headers, comments, sensitive)
	result.Routing, result.RoutingError = resolveRouting(headers, comments, routingLine, sensitive)
	if result.State == StateReady && result.Routing != nil {
		result.RoutingSummary = summarizeRouting(result.Routing, sensitive)
	}
	return result
}

func parseNode(link string, sensitive displayRedactor) (Node, bool) {
	id := nodeID(link)
	if id == "" {
		return Node{}, false
	}
	name := displayText(links.Name(link), nodeNameLimit, sensitive)
	if name == "" {
		protocol, _, _ := strings.Cut(link, "://")
		name = strings.ToUpper(protocol) + " " + id[:8]
	}
	return Node{ID: id, Name: name, Link: strings.Clone(link)}, true
}

func nodeID(link string) string {
	outbound, err := links.Parse(link)
	if err != nil {
		return ""
	}
	canonical, err := json.Marshal(outbound)
	if err != nil {
		return ""
	}
	// Use the parsed dial options so provider order, labels and equivalent link
	// spellings do not affect IDs. Version the input without embedding credentials.
	hash := sha256.New()
	hash.Write([]byte("keenproxy-subscription-node-v1\x00"))
	hash.Write(canonical)
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func decodeShareListBody(body string) string {
	body = trimShareList(body)
	if encoded, ok := strings.CutPrefix(body, "base64:"); ok {
		if decoded, ok := decodeBase64Text(encoded); ok {
			return trimShareList(decoded)
		}
	} else if !strings.ContainsAny(body, ":#") {
		if decoded, ok := decodeBase64Text(body); ok {
			return trimShareList(decoded)
		}
	}
	return body
}

func trimShareList(body string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(body), "\ufeff"))
}

// decodeBase64Text accepts standard and URL-safe alphabets with optional padding.
func decodeBase64Text(encoded string) (string, bool) {
	encoded = strings.TrimSpace(encoded)
	encoding := base64.StdEncoding
	if strings.ContainsAny(encoded, "-_") {
		encoding = base64.URLEncoding
	}
	if !strings.HasSuffix(encoded, "=") {
		encoding = encoding.WithPadding(base64.NoPadding)
	}
	raw, err := encoding.DecodeString(encoded)
	if err != nil || !utf8.Valid(raw) {
		return "", false
	}
	return string(raw), true
}

func collectMetadata(comments http.Header, line string) {
	field, value, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	switch field = strings.ToLower(strings.TrimSpace(field)); field {
	case "profile-title", "announce", "support-url", "profile-web-page-url", "profile-update-interval", "subscription-userinfo", "routing-enable":
		if len(comments.Values(field)) == 0 {
			comments.Set(field, value)
		}
	}
}

const (
	nodeNameLimit = 128
	titleLimit    = 256
	announceLimit = 2048
)

func parseMetadata(headers, comments http.Header, sensitive displayRedactor) Metadata {
	value := func(name string) string {
		if supplied := headers.Values(name); len(supplied) > 0 {
			return strings.TrimSpace(supplied[0])
		}
		return strings.TrimSpace(comments.Get(name))
	}
	metadata := Metadata{
		Title:      providerText(value("profile-title"), titleLimit, sensitive),
		Announce:   providerText(value("announce"), announceLimit, sensitive),
		SupportURL: metadataURL(value("support-url"), sensitive),
		ProfileURL: metadataURL(value("profile-web-page-url"), sensitive),
		Usage:      parseUsage(value("subscription-userinfo")),
	}
	if hours, err := strconv.ParseInt(value("profile-update-interval"), 10, 64); err == nil {
		metadata.UpdateIntervalHours = int(max(1, min(hours, 168)))
	}
	return metadata
}

func providerText(value string, limit int, sensitive displayRedactor) string {
	if raw, ok := strings.CutPrefix(value, "base64:"); ok {
		decoded, ok := decodeBase64Text(raw)
		if !ok {
			return ""
		}
		value = decoded
	}
	return displayText(value, limit, sensitive)
}

func displayText(value string, limit int, sensitive displayRedactor) string {
	if !utf8.ValidString(value) {
		return ""
	}
	value = strings.Map(func(char rune) rune {
		if unicode.IsControl(char) && char != '\n' && char != '\t' {
			if unicode.IsSpace(char) {
				return ' '
			}
			return -1
		}
		return char
	}, value)
	// Redact before truncation so a long credential-bearing URL cannot become
	// a visible partial URL when clipping a title or label.
	value = sensitive.replace(value)
	for offset := range value {
		if limit == 0 {
			value = value[:offset]
			break
		}
		limit--
	}
	return strings.Clone(strings.TrimSpace(value))
}

func metadataURL(value string, sensitive displayRedactor) string {
	if len(value) > 2048 {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || httpsOrigin(u) == "" || sensitive.blocksLink(u, value) {
		return ""
	}
	return u.String()
}

// displayRedactor protects the request URI, hosts reached by the fetch, and
// HWID sent with it before provider data enters the display projection.
type displayRedactor struct {
	hosts      map[string]struct{}
	paths      map[string][]string
	requestURI string
	hwid       string
	// A legacy snapshot has no record of the final same-origin request path.
	blockSameHostLinks bool
}

const redactedDisplay = "[redacted]"

// Runs may contain a bare path or an encoded scheme.
var displayRun = regexp.MustCompile(`[^[:space:]\p{Z}\x{85}<>"]+`)
var displayPercentEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

func sourceDisplayRedactor(u *url.URL) displayRedactor {
	var sensitive displayRedactor
	sensitive.addURL(u)
	// A bare root carries no request-specific text.
	if target := u.RequestURI(); target != "/" {
		sensitive.requestURI = displayURLComparison(decodeDisplayEscapes(target))
	}
	return sensitive
}

func (r *displayRedactor) addURL(u *url.URL) {
	host := displayHost(u.Hostname())
	if r.paths == nil {
		r.hosts = make(map[string]struct{})
		r.paths = make(map[string][]string)
	}
	r.hosts[displayHostKey(host)] = struct{}{}
	r.paths[host] = append(r.paths[host], requestPath(u))
}

func requestPath(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return decodeDisplayEscapes(u.EscapedPath())
}

func (r displayRedactor) replace(value string) string {
	if len(r.hosts) > 0 {
		value = displayRun.ReplaceAllStringFunc(value, func(run string) string {
			comparison := displayURLComparison(decodeDisplayEscapes(run))
			if r.containsHost(comparison) || (r.requestURI != "" && strings.Contains(comparison, r.requestURI)) {
				return redactedDisplay
			}
			return run
		})
	}
	if r.hwid != "" {
		value = strings.ReplaceAll(value, r.hwid, redactedDisplay)
		if strings.Contains(decodeDisplayEscapes(value), r.hwid) {
			return redactedDisplay
		}
	}
	return value
}

func displayHost(host string) string {
	return strings.TrimSuffix(normalizedHost(host, strings.ContainsRune(host, ':')), ".")
}

// Fold the Unicode form of IDNs for matching. The account-link exception
// still uses the canonical IDNA host and its fetched paths.
func displayHostKey(canonical string) string {
	if strings.Contains(canonical, "xn--") {
		if host, err := idna.Lookup.ToUnicode(canonical); err == nil {
			return foldDisplayComparison(host)
		}
	}
	return canonical
}

// containsHost scans the whole comparison string, including embedded URLs.
func (r displayRedactor) containsHost(comparison string) bool {
	for token := range strings.FieldsFuncSeq(comparison, func(char rune) bool {
		return !unicode.In(char, unicode.L, unicode.M, unicode.N) && !strings.ContainsRune("._-:\u3002\uff0e\uff61", char)
	}) {
		// Keep IPv6 addresses intact before treating colons as separators.
		if host := displayHost(token); host != "" {
			if _, protected := r.hosts[displayHostKey(host)]; protected {
				return true
			}
			continue
		}
		for part := range strings.SplitSeq(token, ":") {
			if _, protected := r.hosts[displayHostKey(displayHost(part))]; protected {
				return true
			}
		}
	}
	return false
}

// blocksLink allows a link on a protected host only at a different path
// without a query or fragment. Scan the raw link so malformed form queries
// cannot hide an embedded subscription URL.
func (r displayRedactor) blocksLink(u *url.URL, raw string) bool {
	decoded := decodeDisplayEscapes(raw)
	if r.hwid != "" && strings.Contains(decoded, r.hwid) {
		return true
	}
	if paths, protected := r.paths[displayHost(u.Hostname())]; protected {
		path := requestPath(u)
		if r.blockSameHostLinks || slices.Contains(paths, path) || u.ForceQuery || u.RawQuery != "" || strings.Contains(raw, "#") {
			return true
		}
		// The account-page exception covers the link's host. Its path can
		// still carry an embedded subscription URL.
		decoded = path
	}
	return r.containsHost(displayURLComparison(decoded))
}

func displayURLComparison(decoded string) string {
	return strings.ReplaceAll(foldDisplayComparison(decoded), "+", " ")
}

var displayCaseFold = cases.Fold()

// Default_Ignorable_Code_Point from Unicode 17 DerivedCoreProperties.
var displayIgnorables = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x00ad, Hi: 0x00ad, Stride: 1},
		{Lo: 0x034f, Hi: 0x034f, Stride: 1},
		{Lo: 0x061c, Hi: 0x061c, Stride: 1},
		{Lo: 0x115f, Hi: 0x1160, Stride: 1},
		{Lo: 0x17b4, Hi: 0x17b5, Stride: 1},
		{Lo: 0x180b, Hi: 0x180f, Stride: 1},
		{Lo: 0x200b, Hi: 0x200f, Stride: 1},
		{Lo: 0x202a, Hi: 0x202e, Stride: 1},
		{Lo: 0x2060, Hi: 0x206f, Stride: 1},
		{Lo: 0x3164, Hi: 0x3164, Stride: 1},
		{Lo: 0xfe00, Hi: 0xfe0f, Stride: 1},
		{Lo: 0xfeff, Hi: 0xfeff, Stride: 1},
		{Lo: 0xffa0, Hi: 0xffa0, Stride: 1},
		{Lo: 0xfff0, Hi: 0xfff8, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x1bca0, Hi: 0x1bca3, Stride: 1},
		{Lo: 0x1d173, Hi: 0x1d17a, Stride: 1},
		{Lo: 0xe0000, Hi: 0xe0fff, Stride: 1},
	},
}

func foldDisplayComparison(value string) string {
	value = strings.Map(func(char rune) rune {
		if unicode.Is(displayIgnorables, char) {
			return -1
		}
		return char
	}, value)
	return norm.NFKC.String(displayCaseFold.String(norm.NFKC.String(value)))
}

// Decode valid escapes even when the same value includes stray percent signs.
func decodeDisplayEscapes(value string) string {
	const maxPasses = 4
	for pass := 0; pass < maxPasses && strings.Contains(value, "%"); pass++ {
		decoded := displayPercentEscape.ReplaceAllStringFunc(value, func(escape string) string {
			unescaped, _ := url.PathUnescape(escape)
			return unescaped
		})
		if decoded == value {
			break
		}
		value = decoded
	}
	return value
}

func parseUsage(value string) *Usage {
	var usage Usage
	var populated bool
	for field := range strings.SplitSeq(value, ";") {
		name, amount, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(amount), 10, 64)
		if err != nil || n < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "upload":
			usage.Upload = n
		case "download":
			usage.Download = n
		case "total":
			usage.Total = n
		case "expire":
			usage.Expire = n
		default:
			continue
		}
		populated = true
	}
	if !populated {
		return nil
	}
	return &usage
}
