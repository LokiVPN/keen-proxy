package connectionimport

import (
	"net/url"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// importedIdentity prepares an untrusted label for the wizard. The wizard
// checks the final name and ID again after choosing a unique identifier.
func importedIdentity(draft Draft, label string, secrets []string) Draft {
	draft = credentialDraft(draft, secrets)
	const labelLimit = 160
	name := subscription.ImportedConnectionLabel(label, labelLimit, secrets)
	// Slugging can join words with the same separators used by a credential.
	if name == "" || subscription.ContainsDisplaySecret(Slug(name), secrets) {
		name = strings.TrimSpace(draft.Summary.Protocol + " " + draft.Summary.Server)
	}
	draft.Connection.Name = strings.Join(strings.Fields(name), " ")
	return draft
}

func credentialDraft(draft Draft, secrets []string) Draft {
	draft.secrets = secrets
	if draft.ContainsCredential(draft.Summary.Server) {
		draft.Summary.Server = ""
	}
	if draft.ContainsCredential(draft.Summary.SNI) {
		draft.Summary.SNI = ""
	}
	return draft
}

// ContainsCredential checks the final values without exposing the secret list
// or parsing the draft again.
func (d Draft) ContainsCredential(values ...string) bool {
	for _, value := range values {
		if subscription.ContainsDisplaySecret(value, d.secrets) {
			return true
		}
	}
	return false
}

var profileKeySeparators = strings.NewReplacer("-", "", "_", "")

func normalizedProfileKey(key string) string {
	return strings.ToLower(profileKeySeparators.Replace(key))
}

func credentialField(key string) bool {
	key = normalizedProfileKey(key)
	for _, suffix := range []string{"password", "passwd", "passphrase", "uuid", "token", "key", "psk", "secret"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	switch key {
	case "username", "auth", "authstr", "shortid":
		return true
	default:
		return false
	}
}

func profileSecrets(profile map[string]any) []string {
	var secrets []string
	var collect func(any, bool)
	collect = func(value any, sensitive bool) {
		switch v := value.(type) {
		case string:
			if sensitive && v != "" {
				secrets = append(secrets, v)
			}
		case map[string]any:
			for key, field := range v {
				collect(field, sensitive || credentialField(key))
			}
		case []any:
			for _, item := range v {
				collect(item, sensitive)
			}
		case []map[string]any:
			for _, item := range v {
				collect(item, sensitive)
			}
		case []string:
			for _, item := range v {
				collect(item, sensitive)
			}
		}
	}
	collect(profile, false)
	return secrets
}

func linkSecrets(link string, secrets []string) []string {
	u, err := url.Parse(link)
	if err != nil {
		return secrets
	}
	if u.User != nil {
		password, _ := u.User.Password()
		secrets = append(secrets, u.User.Username(), password)
	}
	// Read named credentials from the saved link even when a protocol's
	// adapter ignores that option. Query text still belongs to the payload.
	for field := range strings.FieldsFuncSeq(u.RawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		key, value, ok := strings.Cut(field, "=")
		key, keyErr := url.QueryUnescape(key)
		if ok && keyErr == nil && credentialField(key) {
			if value, err := url.QueryUnescape(value); err == nil {
				secrets = append(secrets, value)
			}
		}
	}
	return secrets
}
