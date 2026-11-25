package profiledisplay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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

// Credentials collects configured and decoded credential spellings for display checks.
func Credentials(profile any) []string { return profileCredentials(profile, nil) }

// profileCredentials collects recognized dial credentials from nested options.
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
				for _, secret := range StringValues(field) {
					credentials = appendCredentialForms(credentials, secret)
					if strings.EqualFold(key, "password") {
						// Hysteria2 and other combined credentials can repeat
						// the username or password alone in a display value.
						if user, password, combined := strings.Cut(secret, ":"); combined {
							credentials = appendCredentialForms(credentials, user)
							credentials = appendCredentialForms(credentials, password)
						}
					}
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
		for _, value := range StringValues(field) {
			credentials = append(credentials, value)
			credentials = appendAuthorizationForms(credentials, value)
			if strings.EqualFold(key, "Cookie") {
				credentials = appendCookieForms(credentials, value)
			}
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
		if user, password, found := strings.Cut(decodedCredential(parts[1]), ":"); found {
			forms = append(forms, user, password)
		}
	}
	return forms
}

// Cookie values can repeat outside the header that carries them.
func appendCookieForms(forms []string, value string) []string {
	cookies, _ := http.ParseCookie(value)
	for _, cookie := range cookies {
		forms = append(forms, profileStringForms(cookie.Value)...)
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
	if decoded := decodedCredential(value); decoded != "" {
		credentials = append(credentials, decoded)
	}
	return credentials
}

func decodedCredential(value string) string {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := encoding.DecodeString(value); err == nil {
			return string(raw)
		}
	}
	return ""
}

// StringValues accepts scalar or array options from JSON-shaped profiles.
func StringValues(value any) []string {
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
