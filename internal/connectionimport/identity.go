package connectionimport

import (
	"maps"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// importedIdentity keeps the payload values on the server and retains only a
// redacted label as the candidate for the wizard's final identity check.
func importedIdentity(draft Draft, label string, values, nonSummaryValues []string) Draft {
	draft.Summary = redactSummary(draft.Summary, nonSummaryValues)
	draft.secrets = values
	const labelLimit = 160
	name := subscription.ImportedConnectionLabel(label, labelLimit, values)
	draft.Connection.Name = strings.Join(strings.Fields(name), " ")
	if draft.ContainsCredential(draft.Connection.Name) {
		draft.Connection.Name = ""
	}
	return draft
}

func credentialDraft(draft Draft, secrets []string) Draft {
	draft.secrets = secrets
	draft.Summary = redactSummary(draft.Summary, secrets)
	return draft
}

func redactSummary(summary Summary, values []string) Summary {
	if subscription.ContainsDisplaySecret(summary.Server, values) {
		summary.Server = ""
	}
	if subscription.ContainsDisplaySecret(summary.SNI, values) {
		summary.SNI = ""
	}
	return summary
}

// ContainsCredential checks the final values without exposing the inventory
// or parsing the draft again.
func (d Draft) ContainsCredential(values ...string) bool {
	for _, value := range values {
		if subscription.ContainsDisplaySecret(value, d.secrets) {
			return true
		}
	}
	return false
}

// profileValues walks the full imported profile, including nested objects and
// arrays. The selected import label is removed before entering this walk.
func profileValues(values []string, profile any, minimum int) []string {
	switch value := profile.(type) {
	case string:
		values = appendProfileValue(values, value, minimum)
	case map[string]any:
		for _, field := range value {
			values = profileValues(values, field, minimum)
		}
	case []any:
		for _, item := range value {
			values = profileValues(values, item, minimum)
		}
	case []string:
		for _, item := range value {
			values = appendProfileValue(values, item, minimum)
		}
	}
	return values
}

func appendProfileValue(values []string, value string, minimum int) []string {
	if utf8.RuneCountInString(value) < minimum {
		return values
	}
	values = append(values, value)
	// Multiword payloads can contain a standalone value, for example the
	// credentials after an HTTP authentication scheme.
	trimmed := strings.TrimSpace(value)
	if strings.IndexFunc(trimmed, unicode.IsSpace) >= 0 {
		for word := range strings.FieldsSeq(trimmed) {
			if utf8.RuneCountInString(word) >= 3 {
				values = append(values, word)
			}
		}
	}
	return values
}

// nonSummaryProfile leaves out the exact fields projected as type, server
// and SNI. Occurrences elsewhere in the payload still protect the summary.
func nonSummaryProfile(profile map[string]any, endpoint bool) map[string]any {
	rest := maps.Clone(profile)
	delete(rest, "type")
	delete(rest, "server")
	if tls, ok := rest["tls"].(map[string]any); ok {
		tls = maps.Clone(tls)
		delete(tls, "server_name")
		rest["tls"] = tls
	}
	if peers, ok := rest["peers"].([]any); endpoint && ok && len(peers) == 1 {
		if peer, ok := peers[0].(map[string]any); ok {
			peer = maps.Clone(peer)
			delete(peer, "address")
			rest["peers"] = []any{peer}
		}
	}
	return rest
}

func linkValues(link string) (values, nonSummary []string) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil
	}
	if u.User != nil {
		password, _ := u.User.Password()
		values = appendProfileValue(values, u.User.Username(), 1)
		values = appendProfileValue(values, password, 1)
		nonSummary = append(nonSummary, values...)
	}
	for key, list := range u.Query() {
		for _, value := range list {
			values = appendProfileValue(values, value, 1)
			if key != "sni" && key != "peer" {
				nonSummary = appendProfileValue(nonSummary, value, 3)
			}
		}
	}
	return values, nonSummary
}
