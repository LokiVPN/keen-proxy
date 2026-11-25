package profiledisplay

import (
	"bytes"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/gofrs/uuid/v5"
)

// RepeatsCredential compares display strings with the profile's credentials.
// Share links and private connection facts use the same comparison forms.
func RepeatsCredential(credentials []string, values ...string) bool {
	return Repeats([]StringLeaf{{forms: profileComparisonForms(credentials)}}, nil, values...)
}

type StringLeaf struct {
	path  []string
	forms []string
}

// StringLeaves retains every string leaf, including values in fields
// that a particular profile type does not recognize as credentials.
func StringLeaves(profile any, literal func([]string, string) bool) []StringLeaf {
	var leaves []StringLeaf
	walkProfileStrings(reflect.ValueOf(profile), nil, func(path []string, raw string) {
		if raw == "" {
			return
		}
		forms := []string{raw}
		if !literal(path, raw) {
			forms = profileStringForms(raw)
		}
		if len(path) > 0 && strings.EqualFold(path[len(path)-1], "auth") {
			forms = append(forms, decodedProfileBytes(raw))
		}
		if slices.ContainsFunc(path, func(field string) bool { return matchesCredentialField(field, authorizationHeaders) }) {
			forms = appendAuthorizationForms(forms, raw)
		}
		if slices.ContainsFunc(path, func(field string) bool { return strings.EqualFold(field, "Cookie") }) {
			forms = appendCookieForms(forms, raw)
		}
		leaves = append(leaves, StringLeaf{path: slices.Clone(path), forms: profileComparisonForms(forms)})
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
	forms := appendCredentialForms(nil, value)
	if decoded, err := url.PathUnescape(value); err == nil && decoded != value {
		forms = appendCredentialForms(forms, decoded)
	}
	for _, form := range forms {
		scheme, _, _ := strings.Cut(strings.TrimSpace(form), " ")
		if strings.EqualFold(scheme, "Basic") || strings.EqualFold(scheme, "Bearer") {
			forms = appendAuthorizationForms(forms, form)
		}
	}
	return forms
}

// profileComparisonForms adds spellings without changing the original bytes.
// The UUID parser accepts the same representations as the core's clients.
func profileComparisonForms(forms []string) []string {
	for _, form := range forms {
		folded := foldProfileASCII(form)
		if folded != form {
			forms = append(forms, folded)
		}
		if id, err := uuid.FromString(form); err == nil {
			canonical := id.String()
			if canonical != folded {
				forms = append(forms, canonical)
			}
			if compact := strings.ReplaceAll(canonical, "-", ""); compact != folded {
				forms = append(forms, compact)
			}
		}
	}
	return forms
}

// Fold only ASCII runs so UTF-8 and arbitrary high bytes keep their spelling.
func foldProfileASCII(form string) string {
	start := strings.IndexAny(form, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if start < 0 {
		return form
	}
	folded := []byte(form)
	for ascii := range bytes.FieldsFuncSeq(folded[start:], func(r rune) bool { return r > 0x7f }) {
		copy(ascii, bytes.ToLower(ascii))
	}
	return string(folded)
}

// Repeats checks the fact's forms against every other leaf.
// Bytewise containment works even when a credential divides a UTF-8 sequence.
func Repeats(leaves []StringLeaf, source []string, values ...string) bool {
	var forms []string
	for _, value := range values {
		if value != "" {
			forms = append(forms, profileStringForms(value)...)
		}
	}
	forms = profileComparisonForms(forms)
	for _, leaf := range leaves {
		if len(source) > 0 && len(leaf.path) >= len(source) && slices.Equal(leaf.path[:len(source)], source) {
			continue
		}
		for _, form := range forms {
			for _, other := range leaf.forms {
				if other != "" && strings.Contains(form, other) {
					return true
				}
			}
		}
	}
	return false
}
