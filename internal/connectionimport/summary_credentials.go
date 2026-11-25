package connectionimport

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"
)

var profileCredentialFields = []string{
	"username", "password", "uuid", "private_key", "private_key_passphrase", "pre_shared_key",
	"psk", "userkey", "header_protection_key", "short_id", "client_key", "client_key_password",
	"mca_key_password", "auth_str", "token", "access_token", "api_token", "security_token",
	"secret", "access_key_secret", "pin",
}

var authorizationHeaders = []string{
	"Authorization", "Proxy-Authorization", "X-API-Key", "X-Auth-Token", "Cookie",
}

// profileCredentials reads credential fields only for the summary projection.
// Case folding covers the field spellings accepted by sing-box's decoder.
func profileCredentials(value any, credentials []string) []string {
	switch node := value.(type) {
	case map[string]any:
		hysteria := false
		for key, field := range node {
			if strings.EqualFold(key, "type") && field == "hysteria" {
				hysteria = true
			}
		}
		for key, field := range node {
			if strings.EqualFold(key, "headers") {
				headers, _ := field.(map[string]any)
				credentials = headerCredentials(headers, credentials)
				continue
			}
			switch {
			case hysteria && strings.EqualFold(key, "auth"):
				// Hysteria v1 decodes auth as a byte slice, including the
				// JSON byte-array form. Compare what its client actually uses.
				var auth []byte
				if raw, err := json.Marshal(field); err == nil && json.Unmarshal(raw, &auth) == nil {
					credentials = append(credentials, string(auth))
				}
				fallthrough
			case hysteria && strings.EqualFold(key, "obfs"), matchesCredentialField(key, profileCredentialFields):
				for _, secret := range credentialStrings(field) {
					credentials = appendCredentialForms(credentials, secret)
				}
			}
			credentials = profileCredentials(field, credentials)
		}
	case []any:
		for _, item := range node {
			credentials = profileCredentials(item, credentials)
		}
	case []map[string]any:
		for _, item := range node {
			credentials = profileCredentials(item, credentials)
		}
	}
	return credentials
}

func matchesCredentialField(key string, fields []string) bool {
	return slices.ContainsFunc(fields, func(field string) bool { return strings.EqualFold(key, field) })
}

func headerCredentials(headers map[string]any, credentials []string) []string {
	for key, field := range headers {
		if !matchesCredentialField(key, authorizationHeaders) {
			continue
		}
		for _, value := range credentialStrings(field) {
			credentials = append(credentials, value)
			// The credential in a scheme-prefixed header can appear alone.
			if parts := strings.Fields(value); len(parts) == 2 {
				credentials = appendCredentialForms(credentials, parts[1])
				if strings.EqualFold(parts[0], "Basic") {
					if decoded := decodedCredential(parts[1]); decoded != "" {
						if user, password, ok := strings.Cut(decoded, ":"); ok {
							credentials = append(credentials, user, password)
						}
					}
				}
			}
		}
	}
	return credentials
}

// Keep the configured spelling and the textual bytes it may represent. Link
// parsers supply URL-decoded options; the display comparison handles escapes.
func appendCredentialForms(credentials []string, value string) []string {
	credentials = append(credentials, value)
	if decoded := decodedCredential(value); decoded != "" {
		credentials = append(credentials, decoded)
	}
	return credentials
}

func decodedCredential(value string) string {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := encoding.DecodeString(value); err == nil && utf8.Valid(raw) {
			return string(raw)
		}
	}
	return ""
}

func credentialStrings(value any) []string {
	switch field := value.(type) {
	case string:
		return []string{field}
	case []string:
		return field
	case []any:
		var values []string
		for _, item := range field {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
		return values
	default:
		return nil
	}
}
