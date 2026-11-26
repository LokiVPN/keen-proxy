package model

import (
	"iter"
	"slices"
	"strings"
)

// ActiveChain retains fallback order while bypassing disabled profiles. An empty
// effective chain blocks traffic; it must never become an implicit direct exit.
func (c *Config) ActiveChain(id string) []string {
	chain := c.Chain(id)
	active := chain[:0]
	for _, member := range chain {
		if member == TargetDirect {
			active = append(active, member)
			continue
		}
		for _, cn := range c.Connections {
			if cn.ID == member && !cn.Disabled {
				active = append(active, member)
				break
			}
		}
	}
	if len(active) == 0 {
		return append(active, TargetBlock)
	}
	return active
}

// ConnectionFallbackTargets returns the legal reserve choices for an applied
// connection, ordered for display. A disabled profile still has its own
// configured chain and can be selected if the chain is valid.
func (c *Config) ConnectionFallbackTargets(id string) []string {
	incoming := make(map[string][]string, len(c.Connections))
	excluded := []string{id}
	forDNS := c.DNS.Route == "connection" && slices.Contains(c.Chain(c.DNS.Connection), id)
	if forDNS && c.DNS.Failure != "direct" {
		excluded = append(excluded, TargetDirect)
	}
	for _, conn := range c.Connections {
		if conn.Fallback != "" {
			incoming[conn.Fallback] = append(incoming[conn.Fallback], conn.ID)
		}
		if forDNS && !dnsConnectionTypeCanTunnel(conn) {
			excluded = append(excluded, conn.ID)
		}
	}
	// Anything feeding the edited connection would close a loop. The same
	// walk also excludes every path reaching a member disallowed for DNS.
	seen := make(map[string]bool, len(excluded))
	for len(excluded) > 0 {
		target := excluded[len(excluded)-1]
		excluded = excluded[:len(excluded)-1]
		if !seen[target] {
			seen[target] = true
			excluded = append(excluded, incoming[target]...)
		}
	}
	targets := []string{""}
	if !seen[TargetDirect] {
		targets = append(targets, TargetDirect)
	}
	for _, conn := range c.Connections {
		if !seen[conn.ID] {
			targets = append(targets, conn.ID)
		}
	}
	return targets
}

// ActiveEntries yields original entries in order using the canonical entry
// identity for activation. Parent activation never changes persisted child state.
func (g Group) ActiveEntries() iter.Seq[string] {
	return activeValues(g.Entries, g.DisabledEntries, g.Disabled, entryIdentity)
}

func entryIdentity(raw string) string {
	e, err := ParseEntry(raw)
	if err != nil {
		return raw
	}
	return e.String()
}

// ActiveCountries yields enabled country selectors in configuration order.
func (g Group) ActiveCountries() iter.Seq[string] {
	return activeValues(g.Countries, g.DisabledCountries, g.Disabled, geoIdentity)
}

// ActiveCategories yields enabled category selectors in configuration order.
func (g Group) ActiveCategories() iter.Seq[string] {
	return activeValues(g.Categories, g.DisabledCategories, g.Disabled, geoIdentity)
}

func geoIdentity(value string) string { return strings.ToUpper(strings.TrimSpace(value)) }

func activeValues(values, disabled []string, parentOff bool, identity func(string) string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if parentOff {
			return
		}
		var off map[string]bool
		if len(disabled) > 0 {
			off = make(map[string]bool, len(disabled))
			for _, value := range disabled {
				off[identity(value)] = true
			}
		}
		for _, value := range values {
			if len(off) > 0 && off[identity(value)] {
				continue
			}
			if !yield(value) {
				return
			}
		}
	}
}
