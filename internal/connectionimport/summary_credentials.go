package connectionimport

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
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
				credentials = append(credentials, decodedProfileBytes(field))
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
			credentials = appendAuthorizationForms(credentials, value)
		}
	}
	return credentials
}

func appendAuthorizationForms(forms []string, value string) []string {
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return forms
	}
	forms = appendCredentialForms(forms, parts[1])
	if strings.EqualFold(parts[0], "Basic") {
		// Go strings preserve bytes, so split even when the username or
		// password in a legacy Basic header is not valid UTF-8.
		if user, password, found := strings.Cut(decodedCredential(parts[1], false), ":"); found {
			forms = append(forms, user, password)
		}
	}
	return forms
}

func decodedProfileBytes(field any) string {
	var data []byte
	if raw, err := json.Marshal(field); err == nil && json.Unmarshal(raw, &data) == nil {
		return string(data)
	}
	return ""
}

// Keep the configured spelling and the textual bytes it may represent. Link
// parsers supply URL-decoded options; the display comparison handles escapes.
func appendCredentialForms(credentials []string, value string) []string {
	credentials = append(credentials, value)
	if decoded := decodedCredential(value, false); decoded != "" {
		credentials = append(credentials, decoded)
	}
	return credentials
}

func decodedCredential(value string, strict bool) string {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if strict {
			encoding = encoding.Strict()
		}
		if raw, err := encoding.DecodeString(value); err == nil {
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
