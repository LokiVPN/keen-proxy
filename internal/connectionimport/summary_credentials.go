package connectionimport

import (
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
		hysteria := node["type"] == "hysteria"
		for key, field := range node {
			if strings.EqualFold(key, "headers") {
				headers, _ := field.(map[string]any)
				credentials = headerCredentials(headers, credentials)
				continue
			}
			if hysteria && strings.EqualFold(key, "auth") || matchesCredentialField(key, profileCredentialFields) {
				credentials = append(credentials, credentialStrings(field)...)
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
				credentials = append(credentials, parts[1])
			}
		}
	}
	return credentials
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
