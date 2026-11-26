package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/lists"
	"github.com/ordo-systems/keen-proxy/internal/model"
)

// DomainTag is stable when unrelated groups move and changes with group content.
func DomainTag(g model.Group) string {
	raw, _ := json.Marshal(g)
	return "dns-" + shortHash(raw)
}

// shortHash names generated rule sets after their identity.
func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// DomainNames returns sorted, unique domain roots from enabled groups.
func DomainNames(c *model.Config) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, g := range c.Groups {
		if g.Disabled {
			continue
		}
		for raw := range g.ActiveEntries() {
			e, err := model.ParseEntry(raw)
			if err == nil && e.Kind == model.EntryDomain && !seen[e.Domain] {
				seen[e.Domain] = true
				out = append(out, e.Domain)
			}
		}
	}
	sort.Strings(out)
	return out
}

// DomainMatcher normalizes a configuration once, then matches by label suffix.
type DomainMatcher struct{ names map[string]bool }

// NewDomainMatcher indexes normalized group domains for repeated suffix checks.
func NewDomainMatcher(c *model.Config) *DomainMatcher {
	m := &DomainMatcher{names: map[string]bool{}}
	for _, n := range DomainNames(c) {
		m.names[n] = true
	}
	return m
}

// Match accepts an exact domain or any label-delimited subdomain.
func (m *DomainMatcher) Match(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for {
		if m.names[name] {
			return true
		}
		_, rest, ok := strings.Cut(name, ".")
		if !ok {
			return false
		}
		name = rest
	}
}

// DNSNames holds the domain names of one configuration and its applied
// provider rules for DNS: which device answers the DNS fallback keeps, which
// names provider block rules answer locally, and which fallback set an answer
// fills. The daemon builds it once per change of either and shares it
// read-only with the DNS frontend's goroutines.
type DNSNames struct {
	sets  []dnsSet
	index lists.DomainIndex // list positions are positions in sets
	// keywords of the provider domain rules RouteOrder puts before block,
	// which decide a name before any block rule does
	keywords []string
}

// dnsSet is one DNS fallback rule set: an enabled group that is not a country
// or category group, or an enabled provider domain rule with suffix or exact
// names.
type dnsSet struct {
	tag  string
	kind dnsSetKind
}

type dnsSetKind uint8

const (
	setOwn           dnsSetKind = iota // a group that routes traffic: an own list
	setOwnBlock                        // a block group, which DNS blocks on its own
	setProvider                        // a provider rule RouteOrder puts after block
	setProviderFirst                   // a provider rule RouteOrder puts before block
	setProviderBlock                   // a provider block rule
)

// NewDNSNames indexes the DNS fallback sets of c: its enabled entry groups,
// then the enabled domain rules of the provider rules that apply to c
// (providers as in Input) that have suffix or exact names. Keyword and regex
// entries need a readable name and fill no set; only the keywords of rules
// before block take part, in ProviderBlocked.
func NewDNSNames(c *model.Config, providers map[string]ProviderRules) *DNSNames {
	sets, names, keywords := dnsSets(c, providers)
	return &DNSNames{sets: sets, index: lists.NewDomainIndex(names), keywords: keywords}
}

// dnsSets lists the DNS fallback sets of c, groups first, with the names that
// fill each, and the keywords of the provider domain rules that RouteOrder
// puts before block. Groups with equal content share one set.
func dnsSets(c *model.Config, providers map[string]ProviderRules) ([]dnsSet, []lists.DomainList, []string) {
	var sets []dnsSet
	var names []lists.DomainList
	seen := map[string]bool{}
	add := func(tag string, kind dnsSetKind, list lists.DomainList) {
		if !seen[tag] {
			seen[tag] = true
			sets = append(sets, dnsSet{tag: tag, kind: kind})
			names = append(names, list)
		}
	}
	for _, g := range c.Groups {
		if g.Disabled || g.IsGeo() {
			continue
		}
		var suffix []string
		for raw := range g.ActiveEntries() {
			if e, err := model.ParseEntry(raw); err == nil && e.Kind == model.EntryDomain {
				suffix = append(suffix, e.Domain)
			}
		}
		kind := setOwn
		if g.Target == model.TargetBlock {
			kind = setOwnBlock
		}
		add(DomainTag(g), kind, lists.DomainList{Suffix: suffix})
	}
	profile := providerProfile(c, providers)
	first := actionsBeforeBlock(profile)
	var keywords []string
	for _, r := range enabledProviderRules(c, profile) {
		if r.Kind == providerSite && first[r.Action] {
			kept, _ := usableEntries(r.Keyword, nonEmpty) // as routing keeps them
			keywords = append(keywords, kept...)
		}
		if !providerDNSNames(r) {
			continue
		}
		kind := setProvider
		switch {
		case r.Action == providerBlock:
			kind = setProviderBlock
		case first[r.Action]:
			kind = setProviderFirst
		}
		add(providerDNSTag(r.Key), kind, lists.DomainList{Suffix: r.Suffix, Exact: r.Full})
	}
	return sets, names, keywords
}

// actionsBeforeBlock returns the actions that RouteOrder puts before block:
// routing checks their domain rules first, so they decide a name that a
// block rule lists too.
func actionsBeforeBlock(p *ProviderRules) map[string]bool {
	first := map[string]bool{}
	if p == nil {
		return first
	}
	for _, action := range providerActions(p.RouteOrder) {
		if action == providerBlock {
			break
		}
		first[action] = true
	}
	return first
}

// Observed reports whether a device answer for name fills a DNS fallback set.
func (n *DNSNames) Observed(name string) bool { return n.index.Match(name) }

// InGroups reports whether an enabled group lists name. The daemon keeps such
// names fresh itself; provider names last only as long as device answers.
func (n *DNSNames) InGroups(name string) bool {
	found := false
	n.index.Each(name, func(set int) bool {
		kind := n.sets[set].kind
		found = kind == setOwn || kind == setOwnBlock
		return !found
	})
	return found
}

// ProviderBlocked reports whether routing rejects name by a provider block
// rule, so DNS can answer it locally: an enabled block rule lists name as a
// suffix or exact name, and nothing routing checks earlier matches it by
// name. Earlier come own lists that route traffic, then the domain, exact and
// keyword entries of rules RouteOrder puts before block; their regex entries
// are not checked. Block groups are blocked on their own and exempt nothing.
func (n *DNSNames) ProviderBlocked(name string) bool {
	blocked, earlier := false, false
	n.index.Each(name, func(set int) bool {
		switch n.sets[set].kind {
		case setProviderBlock:
			blocked = true
		case setOwn, setProviderFirst:
			earlier = true
		}
		return !earlier
	})
	if !blocked || earlier {
		return false
	}
	// Keywords match the lowercased name as given, like sing-box.
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return !slices.ContainsFunc(n.keywords, func(k string) bool { return strings.Contains(name, k) })
}

// RuleSets returns the DNS fallback rule-set files: for each set the IPv4
// addresses that records, fresh answers by name, hold for its names, or a
// placeholder that matches nothing. The result names every dns-* file the
// configuration uses.
func (n *DNSNames) RuleSets(records map[string][]string) map[string][]byte {
	cidrs := make([][]string, len(n.sets))
	var addrs []string
	for name, ips := range records {
		addrs = addrs[:0]
		for _, ip := range ips {
			if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
				addrs = append(addrs, netip.PrefixFrom(a, 32).String())
			}
		}
		if len(addrs) == 0 {
			continue
		}
		n.index.Each(name, func(set int) bool {
			cidrs[set] = append(cidrs[set], addrs...)
			return true
		})
	}
	out := make(map[string][]byte, len(n.sets))
	for i, s := range n.sets {
		out[s.tag+".json"] = addressRuleSet(cidrs[i])
	}
	return out
}

// addressRuleSet encodes addresses as a sorted rule-set file; no addresses
// give a placeholder that matches nothing.
func addressRuleSet(cidrs []string) []byte {
	slices.Sort(cidrs)
	cidrs = slices.Compact(cidrs)
	if len(cidrs) == 0 {
		cidrs = []string{noSource}
	}
	raw, _ := json.Marshal(obj{"version": 3, "rules": []obj{{"ip_cidr": cidrs}}})
	return raw
}
