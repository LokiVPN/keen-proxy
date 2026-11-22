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
	case "profile-title", "announce", "support-url", "profile-web-page-url", "profile-update-interval", "subscription-userinfo":
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
	if len(value) > 2048 || sensitive.contains(value) {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || httpsOrigin(u) == "" {
		return ""
	}
	normalized := u.String()
	if sensitive.contains(normalized) {
		return ""
	}
	if decoded, err := url.PathUnescape(normalized); err == nil && sensitive.contains(decoded) {
		return ""
	}
	return normalized
}

// displayRedactor recognizes the request values a provider could echo in panel
// text without altering its private share links.
type displayRedactor []string

func (r *displayRedactor) add(value string) {
	if value != "" && !slices.Contains(*r, value) {
		*r = append(*r, value)
	}
}

func (r displayRedactor) replace(value string) string {
	for _, secret := range r {
		value = strings.ReplaceAll(value, secret, "[redacted]")
	}
	return value
}

func (r displayRedactor) contains(value string) bool {
	return slices.ContainsFunc(r, func(secret string) bool { return strings.Contains(value, secret) })
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
