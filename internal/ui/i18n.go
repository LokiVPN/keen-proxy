package ui

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ordo-systems/keen-proxy/locales"
	"gopkg.in/yaml.v3"
)

var translations = loadTranslations()

func loadTranslations() map[string]map[string]string {
	all := make(map[string]map[string]string)
	for _, lang := range []string{"en", "ru"} {
		raw, err := locales.UI(lang)
		if err != nil {
			panic(err)
		}
		var text map[string]string
		if err := yaml.Unmarshal(raw, &text); err != nil {
			panic(fmt.Errorf("UI catalog %s: %w", lang, err))
		}
		all[lang] = text
	}
	for key, value := range all["en"] {
		if value == "" || all["ru"][key] == "" {
			panic("missing UI translation: " + key)
		}
	}
	if len(all["en"]) != len(all["ru"]) {
		panic("UI translation catalogs have different keys")
	}
	return all
}

// language follows the leading browser preference, defaulting to English.
func language(r *http.Request) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language"))), "ru") {
		return "ru"
	}
	return "en"
}

func localized(r *http.Request) map[string]string {
	return translations[language(r)]
}
