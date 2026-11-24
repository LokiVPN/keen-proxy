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
	name := displayText(links.Name(link), 128, sensitive)
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

func parseMetadata(headers, comments http.Header, sensitive displayRedactor) Metadata {
	value := func(name string) string {
		if supplied := headers.Values(name); len(supplied) > 0 {
			return strings.TrimSpace(supplied[0])
		}
		return strings.TrimSpace(comments.Get(name))
	}
	metadata := Metadata{
		Title:      providerText(value("profile-title"), 256, sensitive),
		Announce:   providerText(value("announce"), 2048, sensitive),
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

// displayRedactor protects the hosts and paths reached by a subscription fetch
// and the HWID sent with it. The private share links are kept separately.
type displayRedactor struct {
	paths map[string][]string
	hwid  string
}

const redactedDisplay = "[redacted]"

var displayURLRun = regexp.MustCompile(`(?i)https?://[^[:space:]\p{Z}\x{85}<>"]+`)

func (r *displayRedactor) addURL(u *url.URL) {
	host := normalizedHost(u.Hostname(), strings.HasPrefix(u.Host, "["))
	if r.paths == nil {
		r.paths = make(map[string][]string)
	}
	r.paths[host] = append(r.paths[host], requestPath(u))
}

func requestPath(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func (r displayRedactor) replace(value string) string {
	if len(r.paths) > 0 {
		value = displayURLRun.ReplaceAllStringFunc(value, func(run string) string {
			if _, protected := r.paths[displayURLHost(run)]; protected {
				return redactedDisplay
			}
			return run
		})
	}
	if r.hwid != "" {
		value = strings.ReplaceAll(value, r.hwid, redactedDisplay)
		if strings.Contains(value, "%") && containsEscapedHWID(value, r.hwid) {
			return redactedDisplay
		}
	}
	return value
}

// displayURLHost reads only the authority, so an invalid path or query cannot
// defeat redaction. Decode the host before IDNA lookup and disregard any port.
func displayURLHost(run string) string {
	_, authority, _ := strings.Cut(run, "://")
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	authority = authority[strings.LastIndexByte(authority, '@')+1:]
	bracketed := strings.HasPrefix(authority, "[")
	var host string
	if bracketed {
		var ok bool
		host, _, ok = strings.Cut(authority[1:], "]")
		if !ok {
			return ""
		}
	} else {
		host, _, _ = strings.Cut(authority, ":")
	}
	host, err := url.PathUnescape(host)
	if err != nil {
		return ""
	}
	return normalizedHost(host, bracketed)
}

// blocksLink allows a link on a protected host only at a different path
// without a query or fragment. Check decoded components for embedded secrets.
func (r displayRedactor) blocksLink(u *url.URL, raw string) bool {
	host := normalizedHost(u.Hostname(), strings.HasPrefix(u.Host, "["))
	if paths := r.paths[host]; len(paths) > 0 &&
		(slices.Contains(paths, requestPath(u)) || u.ForceQuery || u.RawQuery != "" || strings.Contains(raw, "#")) {
		return true
	}
	containsSecret := func(value string) bool { return r.replace(value) != value }
	if (r.hwid != "" && strings.Contains(raw, r.hwid)) || containsSecret(u.Path) || containsSecret(u.Fragment) {
		return true
	}
	for key, values := range u.Query() {
		if containsSecret(key) || slices.ContainsFunc(values, containsSecret) {
			return true
		}
	}
	return false
}

var hwidPercentEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// A provider can percent-encode the device ID in prose containing other
// percent signs. Decode valid escapes only for the HWID check.
func containsEscapedHWID(value, hwid string) bool {
	decoded := hwidPercentEscape.ReplaceAllStringFunc(value, func(escape string) string {
		decoded, _ := url.PathUnescape(escape)
		return decoded
	})
	return strings.Contains(decoded, hwid)
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
