// Package connectionimport converts a single user import into candidate
// connection profiles without starting the engine or changing router settings.
package connectionimport

import (
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

	var draft Draft
	var err error
	switch {
	case strings.EqualFold(path.Ext(filename), ".conf") || interfaceSection.MatchString(text):
		draft, err = importConf(raw, text)
	case strings.HasPrefix(text, "{"):
		draft, err = importJSON(text)
	default:
		draft, err = importLink(text)
	}
	if err != nil {
		return nil, err
	}
	if draft.Connection.Name == "" && filename != "" {
		base := path.Base(strings.ReplaceAll(filename, "\\", "/"))
		draft.Connection.Name = strings.TrimSuffix(base, path.Ext(base))
	}
	return []Draft{draft}, nil
}

func importLink(text string) (Draft, error) {
	if strings.IndexFunc(text, unicode.IsSpace) >= 0 {
		return Draft{}, ErrInvalid
	}
	out, err := links.Parse(text)
	if err != nil {
		return Draft{}, ErrInvalid
	}
	return Draft{
		Connection: model.Connection{Type: model.ConnLink, Link: strings.Clone(text), Name: strings.Clone(links.Name(text))},
		Summary:    outboundSummary(out),
	}, nil
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
func importJSON(text string) (Draft, error) {
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
	c := model.Connection{Type: model.ConnSingBox, Name: name}
	if profile.endpoint {
		c.Endpoint = profile.options
		return Draft{Connection: c, Summary: endpointSummary(c.Endpoint)}, nil
	}
	c.Outbound = profile.options
	return Draft{Connection: c, Summary: outboundSummary(c.Outbound)}, nil
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
