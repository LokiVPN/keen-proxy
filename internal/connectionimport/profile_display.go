package connectionimport

import (
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

type profileString struct {
	path  []string
	forms []string
}

// profileDisplayStrings retains every string leaf, including values in fields
// that a particular profile type does not recognize as credentials.
func profileDisplayStrings(profile any) []profileString {
	var leaves []profileString
	walkProfileStrings(reflect.ValueOf(profile), nil, func(path []string, raw string) {
		if raw == "" {
			return
		}
		forms := profileStringForms(raw)
		if len(path) > 0 && strings.EqualFold(path[len(path)-1], "auth") {
			forms = append(forms, decodedProfileBytes(raw))
		}
		if slices.ContainsFunc(path, func(field string) bool { return matchesCredentialField(field, authorizationHeaders) }) {
			forms = appendAuthorizationForms(forms, raw)
		}
		// Cookie values can repeat outside the header that carries them.
		if slices.ContainsFunc(path, func(field string) bool { return strings.EqualFold(field, "Cookie") }) {
			cookies, _ := http.ParseCookie(raw)
			for _, cookie := range cookies {
				forms = append(forms, profileStringForms(cookie.Value)...)
			}
		}
		leaves = append(leaves, profileString{path: slices.Clone(path), forms: forms})
	})
	return leaves
}

func walkProfileStrings(value reflect.Value, path []string, visit func([]string, string)) {
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		walkProfileStrings(value.Elem(), path, visit)
	case reflect.String:
		visit(path, value.String())
	case reflect.Struct:
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if field.IsExported() {
				walkProfileStrings(value.Field(i), append(path, field.Name), visit)
			}
		}
	case reflect.Map:
		for entry := value.MapRange(); entry.Next(); {
			walkProfileStrings(entry.Value(), append(path, entry.Key().String()), visit)
		}
	case reflect.Array, reflect.Slice:
		if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
			visit(path, string(value.Bytes()))
			return
		}
		if len(path) > 0 && strings.EqualFold(path[len(path)-1], "auth") {
			// Hysteria v1 also accepts its byte string as a JSON array.
			visit(path, decodedProfileBytes(value.Interface()))
		}
		for i := range value.Len() {
			walkProfileStrings(value.Index(i), append(path, strconv.Itoa(i)), visit)
		}
	}
}

func profileStringForms(value string) []string {
	forms := []string{value}
	if decoded, err := url.PathUnescape(value); err == nil && decoded != value {
		forms = append(forms, decoded)
	}
	for _, form := range forms {
		// When guessing the encoding, require canonical pad bits. Known
		// encodings such as Basic auth keep their protocol's decoding rules.
		if decoded := decodedCredential(form, true); decoded != "" {
			forms = append(forms, decoded)
		}
	}
	for _, form := range forms {
		scheme, _, _ := strings.Cut(strings.TrimSpace(form), " ")
		if strings.EqualFold(scheme, "Basic") || strings.EqualFold(scheme, "Bearer") {
			forms = appendAuthorizationForms(forms, form)
		}
	}
	return forms
}

// repeatsProfileString excludes only the source of the displayed fact. It
// compares both the input and its display spelling to every other leaf.
func repeatsProfileString(leaves []profileString, source []string, values ...string) bool {
	var forms []string
	for _, value := range values {
		if value != "" {
			forms = append(forms, profileStringForms(value)...)
		}
	}
	for _, leaf := range leaves {
		if len(source) > 0 && len(leaf.path) >= len(source) && slices.Equal(leaf.path[:len(source)], source) {
			continue
		}
		for _, form := range forms {
			for _, other := range leaf.forms {
				if other != "" && (strings.Contains(form, other) ||
					utf8.ValidString(form) && utf8.ValidString(other) && subscription.ContainsDisplaySecret(form, []string{other})) {
					return true
				}
			}
		}
	}
	return false
}
