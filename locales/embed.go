// Package locales embeds the translation catalogs bundled with KeenProxy.
package locales

import "embed"

//go:embed ui.en.yml ui.ru.yml
var ui embed.FS

// UI reads the catalog for the requested UI language.
func UI(lang string) ([]byte, error) {
	return ui.ReadFile("ui." + lang + ".yml")
}
