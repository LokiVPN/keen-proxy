// Package connectionimport converts a single user import into candidate
// connection profiles without starting the engine or changing router settings.
package connectionimport

import (
	"cmp"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ordo-systems/keen-proxy/internal/amnezia"
	"github.com/ordo-systems/keen-proxy/internal/links"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// MaxSize bounds the original UTF-8 text for both pastes and file uploads.
const MaxSize = 2 << 20

var (
	ErrTooLarge = errors.New("connection import exceeds 2 MiB")
	ErrInvalid  = errors.New("invalid connection import")
	ErrMultiple = errors.New("expected one sing-box profile")
)

// Draft carries the private profile and a separate display projection. Only a
// standalone Amnezia export can produce multiple drafts for an explicit choice.
type Draft struct {
	Connection model.Connection
	Summary    Summary
}

// Parse detects the format of one bounded connection input. Filename is used
// for .conf detection and as a suggested name when the profile has none.
func Parse(raw, filename string) ([]Draft, error) {
	if len(raw) > MaxSize {
		return nil, ErrTooLarge
	}
	if !utf8.ValidString(raw) || strings.ContainsRune(raw, '\x00') {
		return nil, ErrInvalid
	}
	text := strings.TrimSpace(strings.TrimPrefix(raw, "\uFEFF"))
	if text == "" {
		return nil, ErrInvalid
	}
	scheme, body, hasScheme := strings.Cut(text, "://")
	if hasScheme && strings.EqualFold(scheme, "vpn") {
		return importAmnezia("vpn://" + body)
	}

	base := path.Base(strings.ReplaceAll(filename, "\\", "/"))
	fallback := ""
	if filename != "" {
		fallback = strings.TrimSuffix(base, path.Ext(base))
	}
	var draft Draft
	var err error
	switch {
	case strings.EqualFold(path.Ext(filename), ".conf") || interfaceSection.MatchString(text):
		draft, err = importConf(raw, text, fallback)
	case strings.HasPrefix(text, "{"):
		draft, err = importJSON(text, fallback)
	default:
		draft, err = importLink(text, fallback)
	}
	if err != nil {
		return nil, err
	}
	return []Draft{draft}, nil
}

func importLink(text, fallback string) (Draft, error) {
	if strings.IndexFunc(text, unicode.IsSpace) >= 0 {
		return Draft{}, ErrInvalid
	}
	out, err := links.Parse(text)
	if err != nil {
		return Draft{}, ErrInvalid
	}
	draft := Draft{
		Connection: model.Connection{Type: model.ConnLink, Link: strings.Clone(text)},
		Summary:    outboundSummary(out),
	}
	return importedIdentity(draft, cmp.Or(links.Name(text), fallback), linkSecrets(text, profileSecrets(out))), nil
}

func importAmnezia(uri string) ([]Draft, error) {
	connections, err := amnezia.Import(uri)
	if err != nil {
		return nil, err
	}
	drafts := make([]Draft, 0, len(connections))
	for _, connection := range connections {
		draft, err := amneziaDraft(connection)
		if err != nil {
			return nil, err
		}
		drafts = append(drafts, draft)
	}
	return drafts, nil
}

type jsonProfile struct {
	options  map[string]any
	endpoint bool
}

// importJSON accepts an individual profile or the profile containers of a
// sing-box file. Global inbounds, routing, DNS and experimental settings are
// never copied. Built-in actions do not count as connection profiles.
func importJSON(text, fallback string) (Draft, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &root); err != nil {
		return Draft{}, ErrInvalid
	}
	profile, err := oneJSONProfile(root, json.RawMessage(text))
	if err != nil {
		return Draft{}, err
	}
	name, _ := profile.options["tag"].(string)
	delete(profile.options, "tag")
	var draft Draft
	draft.Connection.Type = model.ConnSingBox
	if profile.endpoint {
		draft.Connection.Endpoint = profile.options
		draft.Summary = endpointSummary(profile.options)
	} else {
		draft.Connection.Outbound = profile.options
		draft.Summary = outboundSummary(profile.options)
	}
	return importedIdentity(draft, cmp.Or(name, fallback), profileSecrets(profile.options)), nil
}

func oneJSONProfile(root map[string]json.RawMessage, raw json.RawMessage) (jsonProfile, error) {
	var profile jsonProfile
	var wrapped bool
	add := func(data json.RawMessage, endpoint bool) error {
		var options map[string]any
		if err := json.Unmarshal(data, &options); err != nil {
			return ErrInvalid
		}
		kind, _ := options["type"].(string)
		switch kind {
		case "":
			return ErrInvalid
		case "direct", "block", "dns", "selector", "urltest":
			return nil
		}
		if profile.options != nil {
			return ErrMultiple
		}
		profile = jsonProfile{options: options, endpoint: endpoint}
		return nil
	}
	for _, field := range []string{"outbound", "endpoint"} {
		if single, ok := root[field]; ok {
			wrapped = true
			if err := add(single, field == "endpoint"); err != nil {
				return jsonProfile{}, err
			}
		}
		if plural, ok := root[field+"s"]; ok {
			wrapped = true
			var list []json.RawMessage
			if err := json.Unmarshal(plural, &list); err != nil || list == nil {
				return jsonProfile{}, ErrInvalid
			}
			for _, item := range list {
				if err := add(item, field == "endpoint"); err != nil {
					return jsonProfile{}, err
				}
			}
		}
	}
	if !wrapped {
		var kind string
		_ = json.Unmarshal(root["type"], &kind)
		switch kind {
		case "wireguard", "tailscale", "openvpn", "openconnect":
			if err := add(raw, true); err != nil {
				return jsonProfile{}, err
			}
		default:
			if err := add(raw, false); err != nil {
				return jsonProfile{}, err
			}
		}
	}
	if profile.options == nil {
		return jsonProfile{}, ErrInvalid
	}
	return profile, nil
}
