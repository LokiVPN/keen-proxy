// Package compile deterministically converts configuration into sing-box JSON
// and a firewall plan without runtime side effects.
package compile

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	tagTCPIn  = "tcp-in"
	tagUDPIn  = "udp-in"
	tagDirect = "direct"
)

// Input combines validated configuration with runtime address information.
type Input struct {
	Config *model.Config
	// Neighbors maps MAC addresses to ARP/DHCP addresses for clients without static IPs.
	Neighbors map[string]netip.Addr
	// RuleSetDir holds local rule-set files referenced by the generated configuration.
	RuleSetDir string
	// Subscriptions provides already validated node snapshots, keyed by source ID.
	Subscriptions map[string][]subscription.Node
	// ProviderRules holds the provider rules of subscriptions, keyed by source
	// ID. Only the active rules source in Config applies. Compile only reads
	// them: they share storage with the daemon's state.
	ProviderRules map[string]ProviderRules
}

// Output contains the engine configuration and runtime artifacts to apply.
type Output struct {
	// SingBox depends on configuration, not current client addresses, so address
	// changes do not require an engine restart.
	SingBox []byte
	// RuleSets maps filenames to local rule-set contents. sing-box watches these
	// files for changes, including updates to client class addresses.
	RuleSets map[string][]byte
	// Countries lists ISO codes whose geoip-<code>.json files the daemon must
	// populate with country prefixes in RuleSetDir.
	Countries []string
	// Categories lists labels whose geocat-<label>.json files the daemon must
	// populate from category databases.
	Categories []string
	// ServerHosts maps connection IDs to server addresses or hostnames.
	ServerHosts map[string]string
	// Failover describes chains the daemon probes and switches through selectors.
	Failover []FailoverChain
	// TargetAliases maps configured targets to their compiled outbound tags.
	TargetAliases map[string]string
	// SubscriptionSelectors retain provider priority for the daemon's selection policy.
	SubscriptionSelectors []SubscriptionSelector
	// SubscriptionBalances lists targets whose eligibility is supplied by the daemon.
	SubscriptionBalances []SubscriptionBalance
	// SubscriptionOutbounds identifies the managed nodes that exist in the engine.
	SubscriptionOutbounds []string
	// DroppedProviderEntries counts provider rule entries left out because
	// sing-box would reject them or they would match every name: invalid
	// regexes and empty values.
	DroppedProviderEntries int
	Plan                   netfilter.Plan
	// Split tells which device addresses follow a split policy, the only
	// policies provider rules route; the daemon limits provider DNS blocks
	// to them.
	Split SplitAddresses
}

// Client classes depend only on configuration; address updates change file
// contents without changing the class set.
const (
	classOff     = "clients-off"
	classSplit   = "clients-split"
	classSplitTo = "clients-split-to-" // + default target
	classFull    = "clients-full-"     // + connection ID
)

// noSource keeps empty classes from matching every source.
const noSource = "255.255.255.255/32"

// policy assigns routing behavior to one client or network prefix.
type policy struct {
	source netip.Prefix
	mode   model.Mode
	target string
	// fallback is the outbound for split traffic matching no rule; empty means direct.
	fallback string
	// proxy is the outbound of provider proxy rules in split mode; empty means
	// direct. It stays empty while no provider rules apply, so it separates
	// policies only when provider rules use it.
	proxy string
}

// splitRoute resolves where a split policy with target and network default
// def sends provider proxy rules and unmatched traffic; "" means direct.
// profile follows the applied provider profile: direct when it says
// GlobalProxy false, otherwise and without provider rules the target, so a
// missing profile never sends tunnel traffic direct.
func splitRoute(def, target string, rules *ProviderRules) (fallback, proxy string) {
	if rules != nil {
		proxy = target
	}
	if def == model.DefaultProfile {
		def = target
		if rules != nil && !rules.GlobalProxy {
			def = ""
		}
	}
	if def == model.TargetDirect {
		def = ""
	}
	return def, proxy
}

// Compile builds runtime artifacts from a configuration that has passed Validate.
func Compile(in Input) (Output, error) {
	if in.Config.Paused {
		in.Config = pausedConfig(in.Config)
	}
	c := in.Config
	rules := providerProfile(c, in.ProviderRules)
	clients, networks, excluded := policies(in, rules)

	var sources []netip.Prefix
	for _, p := range append(append([]policy{}, clients...), networks...) {
		if p.mode == model.ModeSplit || p.mode == model.ModeFull {
			sources = append(sources, p.source)
		}
	}
	conns, err := connections(c)
	if err != nil {
		return Output{}, err
	}
	bypass := netfilter.DefaultBypass()
	for _, a := range conns.servers {
		bypass = append(bypass, netip.PrefixFrom(a, a.BitLen()))
	}
	var dnsBypass []netip.Addr
	if len(c.DNS.BypassSources) > 0 {
		dnsBypass = make([]netip.Addr, 0, len(c.DNS.BypassSources))
		seen := make(map[netip.Addr]struct{}, len(c.DNS.BypassSources))
		for _, source := range c.DNS.BypassSources {
			addr, _ := netip.ParseAddr(source) // validated by model
			if _, exists := seen[addr]; exists {
				continue
			}
			seen[addr] = struct{}{}
			dnsBypass = append(dnsBypass, addr)
		}
	}

	chains, tags := failover(c)
	managed, err := compileSubscriptions(in, tags)
	if err != nil {
		return Output{}, err
	}
	conns.outbounds = append(conns.outbounds, managed.outbounds...)
	classes := clientClasses(c, rules)
	provider := compileProviderRules(c, rules, in.RuleSetDir)
	sb, err := json.MarshalIndent(singBox(c, in.RuleSetDir, networks, conns, chains, tags, managed, classes, provider), "", "  ")
	if err != nil {
		return Output{}, err
	}
	_, _, _, geo := groupRuleSets(c.Groups, in.RuleSetDir, nil)
	sets, err := clientRuleSets(clients, classes)
	if err != nil {
		return Output{}, err
	}
	maps.Copy(sets, provider.files)
	// The daemon fills the DNS fallback sets with observed answers.
	dns, _, _ := dnsSets(c, in.ProviderRules)
	maps.Copy(sets, (&DNSNames{sets: dns}).RuleSets(nil))
	return Output{
		SingBox:                sb,
		RuleSets:               sets,
		Countries:              geo.countries,
		Categories:             geo.categories,
		ServerHosts:            conns.hosts,
		Failover:               chains,
		TargetAliases:          tags,
		SubscriptionSelectors:  managed.selectors,
		SubscriptionBalances:   managed.balances,
		SubscriptionOutbounds:  managed.nodeTags,
		DroppedProviderEntries: provider.dropped,
		Split:                  splitAddresses(clients, networks),
		Plan: netfilter.Plan{
			BlockEncryptedDNS: c.DNS.BlockEncrypted,
			DNSBypassSources:  dnsBypass,
			Mode:              c.Intercept.Mode,
			LAN:               c.LAN.Interface,
			DNSPort:           mustPort(c.DNS.Listen),
			TCPPort:           c.Intercept.TCPPort,
			UDPPort:           c.Intercept.UDPPort,
			FWMark:            c.Intercept.FWMark,
			Sources:           sources,
			Excluded:          excluded,
			Bypass:            bypass,
		},
	}, nil
}

// pausedConfig returns a copy where every network and client is off, so no
// interception rules are produced while the daemon keeps running.
func pausedConfig(src *model.Config) *model.Config {
	c := *src
	c.Networks = append([]model.Network(nil), c.Networks...)
	for i := range c.Networks {
		c.Networks[i].Mode = model.ModeOff
	}
	c.Clients = append([]model.Client(nil), c.Clients...)
	for i := range c.Clients {
		c.Clients[i].Mode = model.ModeOff
	}
	return &c
}

// policies resolves client inheritance and network rules. Client rules take
// precedence over networks; excluded clients bypass interception even inside
// participating networks. rules are the applied provider rules, or nil.
func policies(in Input, rules *ProviderRules) (clients, networks []policy, excluded []netip.Addr) {
	c := in.Config
	type netPol struct {
		prefix netip.Prefix
		n      model.Network
	}
	var nets []netPol
	for _, n := range c.Networks {
		p, _ := netip.ParsePrefix(n.CIDR)
		nets = append(nets, netPol{p.Masked(), n})
		pol := policy{source: p.Masked(), mode: n.Mode, target: n.Target}
		pol.fallback, pol.proxy = splitRoute(n.Default, n.Target, rules)
		networks = append(networks, pol)
	}
	for _, cl := range c.Clients {
		ip, ok := clientIP(cl, in.Neighbors)
		if !ok {
			continue // client has no current address
		}
		var network *model.Network
		for i := range nets {
			if nets[i].prefix.Contains(ip) {
				network = &nets[i].n
				break
			}
		}
		pol, ok := clientPolicy(cl, network, rules)
		if !ok {
			continue
		}
		pol.source = netip.PrefixFrom(ip, ip.BitLen())
		if pol.mode == model.ModeOff {
			if network != nil && network.Mode != model.ModeOff {
				excluded = append(excluded, ip)
				clients = append(clients, pol)
			}
			continue
		}
		clients = append(clients, pol)
	}
	return clients, networks, excluded
}

// clientPolicy applies a client's own mode and target over the network that
// contains its address (nil for none); ok is false when the client inherits
// from no network. The result has no source.
func clientPolicy(cl model.Client, network *model.Network, rules *ProviderRules) (policy, bool) {
	p := policy{mode: cl.Mode, target: cl.Target}
	var def string
	if network != nil {
		if p.mode == model.ModeInherit {
			p.mode = network.Mode
		}
		if p.target == "" {
			p.target = network.Target
		}
		def = network.Default
	} else if p.mode == model.ModeInherit {
		return policy{}, false
	}
	p.fallback, p.proxy = splitRoute(def, p.target, rules)
	return p, true
}

// SplitAddresses resolves whether a device address follows a split policy as
// the route rules do: the client entry holding the address decides first,
// otherwise the first network holding it. A paused router has none.
type SplitAddresses struct {
	clients  map[netip.Addr]bool
	networks []policy // in configuration order
}

// Contains reports whether the device at a follows a split policy.
func (s SplitAddresses) Contains(a netip.Addr) bool {
	a = a.Unmap()
	if split, ok := s.clients[a]; ok {
		return split
	}
	for _, n := range s.networks {
		if n.source.Contains(a) {
			return n.mode == model.ModeSplit
		}
	}
	return false
}

// splitAddresses indexes the resolved policies. Clients that share an
// address count as split only when all are, because off and full-tunnel
// classes come before split ones in the route rules.
func splitAddresses(clients, networks []policy) SplitAddresses {
	s := SplitAddresses{clients: make(map[netip.Addr]bool, len(clients)), networks: networks}
	for _, p := range clients {
		a := p.source.Addr()
		split, seen := s.clients[a]
		s.clients[a] = p.mode == model.ModeSplit && (split || !seen)
	}
	return s
}

// clientIP prefers a configured static address over a normalized MAC neighbor lookup.
func clientIP(cl model.Client, neighbors map[string]netip.Addr) (netip.Addr, bool) {
	if cl.IP != "" {
		a, err := netip.ParseAddr(cl.IP)
		return a, err == nil
	}
	mac, err := net.ParseMAC(cl.MAC)
	if err != nil {
		return netip.Addr{}, false
	}
	a, ok := neighbors[mac.String()]
	return a, ok
}

// obj is a JSON-shaped engine configuration node.
type obj = map[string]any

// FailoverChain describes a sing-box selector and its ordered fallback members.
type FailoverChain struct {
	ID    string   // connection referenced by groups and clients
	Tag   string   // selector tag
	Chain []string // enabled IDs in priority order; may end in direct, or contain only block
}

// FailoverTagPrefix plus a connection ID names its fallback selector.
const FailoverTagPrefix = "failover-"

// failover maps route targets to selectors while preserving connection IDs on
// actual outbounds so statistics and journals identify the selected connection.
func failover(c *model.Config) ([]FailoverChain, map[string]string) {
	var chains []FailoverChain
	tags := map[string]string{}
	for _, cn := range c.Connections {
		if cn.Fallback == "" && !cn.Disabled {
			continue
		}
		fc := FailoverChain{ID: cn.ID, Tag: FailoverTagPrefix + cn.ID, Chain: c.ActiveChain(cn.ID)}
		chains = append(chains, fc)
		tags[cn.ID] = fc.Tag
	}
	return chains, tags
}

// singBox orders global blocks, client policies, and network policies after sniffing.
func singBox(c *model.Config, ruleSetDir string, networks []policy, conns connOut, chains []FailoverChain, tags map[string]string, managed subscriptionRouting, classes []class, provider providerRouting) obj {
	inbounds := []obj{{"type": "redirect", "tag": tagTCPIn, "listen": "0.0.0.0", "listen_port": c.Intercept.TCPPort}}
	sniffIn := []string{tagTCPIn}
	if c.Intercept.Mode == model.InterceptTProxy {
		inbounds = append(inbounds, obj{"type": "tproxy", "tag": tagUDPIn, "listen": "0.0.0.0", "listen_port": c.Intercept.UDPPort, "network": "udp"})
		sniffIn = append(sniffIn, tagUDPIn)
	}

	ruleSets, blockSets, groupSets, _ := groupRuleSets(c.Groups, ruleSetDir, provider.steps)
	ruleSets = append(ruleSets, provider.sets...)
	rules := []obj{
		{"inbound": sniffIn, "action": "sniff"},
		{"ip_is_private": true, "outbound": tagDirect},
	}
	for _, b := range blockSets {
		r := b.match()
		r["action"] = "reject"
		rules = append(rules, r)
	}
	clientSets, clientRules := clientRouting(ruleSetDir, groupSets, tags, classes)
	ruleSets = append(clientSets, ruleSets...)
	rules = append(rules, clientRules...)
	rules = append(rules, sourceRules(networks, groupSets, tags)...)

	route := obj{"rules": rules, "final": tagDirect}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	// Raw dependencies keep their configured tag without starting its disabled transport.
	for i := range c.Connections {
		cn := &c.Connections[i]
		if cn.Disabled {
			conns.outbounds = append(conns.outbounds, obj{
				"type": "selector", "tag": cn.ID, "outbounds": []string{tags[cn.ID]},
			})
		}
	}
	cfg := obj{
		"log":       obj{"level": "warn", "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": append(append([]obj{{"type": "direct", "tag": tagDirect}}, conns.outbounds...), managedOutbounds(chains, managed)...),
		"route":     route,
	}
	if len(conns.endpoints) > 0 {
		cfg["endpoints"] = conns.endpoints
	}
	return cfg
}

// managedOutbounds emits selectors and per-connection policies after their concrete nodes.
func managedOutbounds(chains []FailoverChain, managed subscriptionRouting) []obj {
	var out []obj
	blockAdded := managed.block
	if blockAdded {
		out = append(out, obj{"type": "block", "tag": model.TargetBlock})
	}
	for _, fc := range chains {
		if fc.Chain[0] == model.TargetBlock && !blockAdded {
			out = append(out, obj{"type": "block", "tag": model.TargetBlock})
			blockAdded = true
		}
		out = append(out, obj{
			"type": "selector", "tag": fc.Tag, "outbounds": fc.Chain, "default": fc.Chain[0],
			"interrupt_exist_connections": true,
		})
	}
	for _, selector := range managed.selectors {
		out = append(out, managedSelector(selector))
	}
	for _, balance := range managed.balances {
		o := obj{"type": model.SubscriptionBalanceOutboundType, "tag": balance.Tag, "outbounds": balance.Candidates}
		if balance.Fallback != "" {
			o["fallback"] = balance.Fallback
		}
		out = append(out, o)
	}
	return out
}

// groupSet associates shared match sets with a target and optional country
// exclusion. In a split policy it is one step of the rule chain.
type groupSet struct {
	tags   []string // one set per country for country groups
	target string   // block rejects in a split policy
	// proxy sends matching traffic to the policy's proxy outbound instead of
	// target (provider proxy rules).
	proxy bool
	// invert matches addresses outside the union of country sets.
	invert bool
	dns    bool
}

// match combines group sets with OR and optionally inverts their entire union.
func (g groupSet) match() obj {
	m := obj{"rule_set": g.tags}
	if g.invert {
		m["invert"] = true
	}
	if g.dns {
		return obj{"type": "logical", "mode": "and", "rules": []obj{m, {"domain_regex": []string{".+"}, "invert": true}}}
	}
	return m
}

// send completes a split policy rule with where its traffic goes: reject for
// a block step, the policy's proxy outbound for a provider proxy step,
// otherwise the step's target.
func (g groupSet) send(rule obj, p policy, tags map[string]string) obj {
	switch {
	case g.target == model.TargetBlock:
		rule["action"] = "reject"
	case g.proxy:
		rule["outbound"] = outboundTag(p.proxy, tags)
	default:
		rule["outbound"] = outboundTag(g.target, tags)
	}
	return rule
}

// Rule-set tag prefixes of the local sets the daemon fills from IP databases.
const (
	CountryTagPrefix  = "geoip-"
	CategoryTagPrefix = "geocat-"
)

// geoCodes lists the country codes and category labels whose local rule-set
// files the daemon must populate.
type geoCodes struct{ countries, categories []string }

// groupRuleSets shares inline entry sets across sources and references local
// geoip-<code> and geocat-<label> sets for IP-database groups. Explicit domain
// and address groups precede those groups regardless of configuration order;
// the provider steps go between them, so own lists win over provider rules
// and country groups stay last.
func groupRuleSets(groups []model.Group, dir string, provider []groupSet) (sets []obj, block, routed []groupSet, geo geoCodes) {
	var countryBlock, countryRouted []groupSet
	seen := map[string]bool{}
	for i, g := range groups {
		if g.Disabled {
			continue
		}
		if g.IsGeo() {
			gs := groupSet{target: g.Target, invert: g.Except}
			add := func(prefix, code string, list *[]string) {
				tag := prefix + strings.ToLower(code)
				gs.tags = append(gs.tags, tag)
				if !seen[tag] {
					seen[tag] = true
					*list = append(*list, code)
					sets = append(sets, localRuleSet(tag, dir))
				}
			}
			for cc := range g.ActiveCountries() {
				add(CountryTagPrefix, cc, &geo.countries)
			}
			for cat := range g.ActiveCategories() {
				add(CategoryTagPrefix, cat, &geo.categories)
			}
			if len(gs.tags) == 0 {
				continue
			}
			if g.Target == model.TargetBlock {
				countryBlock = append(countryBlock, gs)
			} else {
				countryRouted = append(countryRouted, gs)
			}
			continue
		}
		var domains, cidrs []string
		for raw := range g.ActiveEntries() {
			e, err := model.ParseEntry(raw)
			if err != nil {
				continue
			}
			if e.Kind == model.EntryDomain {
				domains = append(domains, e.Domain)
			} else {
				cidrs = append(cidrs, e.Prefix.String())
			}
		}
		if len(domains) == 0 && len(cidrs) == 0 {
			continue
		}
		rule := obj{}
		if len(domains) > 0 {
			rule["domain_suffix"] = domains
		}
		if len(cidrs) > 0 {
			rule["ip_cidr"] = cidrs
		}
		tag := "group-" + strconv.Itoa(i)
		sets = append(sets, obj{"type": "inline", "tag": tag, "rules": []obj{rule}})
		gs := groupSet{tags: []string{tag}, target: g.Target}
		if g.Target == model.TargetBlock {
			block = append(block, gs)
		} else {
			routed = append(routed, gs)
		}
	}

	var dnsBlock, dnsRouted []groupSet
	declaredDNS := map[string]bool{}
	for _, g := range groups {
		if g.Disabled {
			continue
		}
		if g.IsGeo() {
			continue
		}
		tag := DomainTag(g)
		if !declaredDNS[tag] {
			sets = append(sets, localRuleSet(tag, dir))
			declaredDNS[tag] = true
		}
		gs := groupSet{tags: []string{tag}, target: g.Target, dns: true}
		if g.Target == model.TargetBlock {
			dnsBlock = append(dnsBlock, gs)
		} else {
			dnsRouted = append(dnsRouted, gs)
		}
	}
	sort.Strings(geo.countries)
	sort.Strings(geo.categories)
	routed = append(append(routed, dnsRouted...), provider...)
	return sets, append(append(block, countryBlock...), dnsBlock...), append(routed, countryRouted...), geo
}

// sourceRules preserves policy order while merging adjacent policies with
// identical routing behavior.
func sourceRules(pols []policy, groups []groupSet, tags map[string]string) []obj {
	outbound := func(target string) string { return outboundTag(target, tags) }
	var rules []obj
	for i := 0; i < len(pols); {
		j := i + 1
		for j < len(pols) && pols[j].mode == pols[i].mode && ((pols[i].mode == model.ModeSplit && pols[j].fallback == pols[i].fallback && pols[j].proxy == pols[i].proxy) || (pols[i].mode != model.ModeSplit && pols[j].target == pols[i].target)) {
			j++
		}
		var src []string
		for _, p := range pols[i:j] {
			src = append(src, p.source.String())
		}
		sort.Strings(src)
		switch pols[i].mode {
		case model.ModeOff:
			rules = append(rules, obj{"source_ip_cidr": src, "outbound": tagDirect})
		case model.ModeFull:
			rules = append(rules, obj{"source_ip_cidr": src, "outbound": outbound(pols[i].target)})
		case model.ModeSplit:
			for _, g := range groups {
				if g.invert || g.dns {
					// A top-level invert would also negate the source condition.
					rules = append(rules, g.send(obj{
						"type": "logical", "mode": "and",
						"rules": []obj{{"source_ip_cidr": src}, g.match()},
					}, pols[i], tags))
					continue
				}
				rules = append(rules, g.send(obj{"source_ip_cidr": src, "rule_set": g.tags}, pols[i], tags))
			}
			rules = append(rules, obj{"source_ip_cidr": src, "outbound": outbound(pols[i].fallback)})
		}
		i = j
	}
	return rules
}

// class is a stable address set of clients that route alike, with the
// routing they share (pol has no source).
type class struct {
	name string
	pol  policy
}

// clientClass maps a resolved client policy to its shared address set. A
// split class with a provider proxy outbound is named after a hash of its
// route: connection IDs are free text, so joining two of them into a name
// could make different routes share a class.
func clientClass(p policy) string {
	switch {
	case p.mode == model.ModeSplit && p.proxy != "":
		return classSplit + "-" + shortHash([]byte(p.proxy+"\x00"+p.fallback))
	case p.mode == model.ModeSplit && p.fallback != "":
		return classSplitTo + p.fallback
	case p.mode == model.ModeSplit:
		return classSplit
	case p.mode == model.ModeFull && p.target != "" && p.target != model.TargetDirect:
		return classFull + p.target
	default: // off and full-direct policies both bypass the tunnel
		return classOff
	}
}

// clientClasses lists stable classes even when no clients currently occupy
// them. Split classes cover every route a configured client can take in any
// network, or outside them, so address changes never change the set.
func clientClasses(c *model.Config, rules *ProviderRules) []class {
	classes := []class{{classOff, policy{mode: model.ModeOff}}}
	for _, cn := range c.Connections {
		classes = append(classes, class{classFull + cn.ID, policy{mode: model.ModeFull, target: cn.ID}})
	}
	for _, target := range subscriptionTargets(c) {
		classes = append(classes, class{classFull + target, policy{mode: model.ModeFull, target: target}})
	}
	classes = append(classes, class{classSplit, policy{mode: model.ModeSplit}})
	split := map[string]policy{}
	add := func(p policy, ok bool) {
		if !ok || p.mode != model.ModeSplit {
			return
		}
		if name := clientClass(p); name != classSplit {
			split[name] = p
		}
	}
	for _, cl := range c.Clients {
		add(clientPolicy(cl, nil, rules))
		for i := range c.Networks {
			add(clientPolicy(cl, &c.Networks[i], rules))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(split)) {
		classes = append(classes, class{name, split[name]})
	}
	return classes
}

// clientRouting orders client class rules before network rules: disabled
// clients, full-tunnel classes by connection, then split routing.
func clientRouting(dir string, groups []groupSet, tags map[string]string, classes []class) (sets, rules []obj) {
	for _, cl := range classes {
		sets = append(sets, localRuleSet(cl.name, dir))
		switch cl.pol.mode {
		case model.ModeOff:
			rules = append(rules, obj{"rule_set": []string{cl.name}, "outbound": tagDirect})
		case model.ModeFull:
			rules = append(rules, obj{"rule_set": []string{cl.name}, "outbound": outboundTag(cl.pol.target, tags)})
		case model.ModeSplit:
			for _, g := range groups {
				// Multiple rule_set values are ORed; use a logical rule for AND.
				rules = append(rules, g.send(obj{
					"type": "logical", "mode": "and",
					"rules": []obj{{"rule_set": []string{cl.name}}, g.match()},
				}, cl.pol, tags))
			}
			rules = append(rules, obj{"rule_set": []string{cl.name}, "outbound": outboundTag(cl.pol.fallback, tags)})
		}
	}
	return sets, rules
}

// clientRuleSets fills stable classes with current addresses and nonmatching empty placeholders.
func clientRuleSets(clients []policy, classes []class) (map[string][]byte, error) {
	byClass := map[string][]string{}
	for _, p := range clients {
		cl := clientClass(p)
		byClass[cl] = append(byClass[cl], p.source.String())
	}
	out := map[string][]byte{}
	for _, cl := range classes {
		src := byClass[cl.name]
		if len(src) == 0 {
			src = []string{noSource}
		}
		sort.Strings(src)
		raw, err := json.MarshalIndent(obj{"version": 3, "rules": []obj{{"source_ip_cidr": src}}}, "", "  ")
		if err != nil {
			return nil, err
		}
		out[cl.name+".json"] = raw
	}
	return out, nil
}

// outboundTag resolves a target to direct, a fallback selector, or a connection.
func outboundTag(target string, tags map[string]string) string {
	if target == "" || target == model.TargetDirect {
		return tagDirect
	}
	if t, ok := tags[target]; ok {
		return t
	}
	return target
}

// mustPort relies on prior model validation and panics on an invalid listen address.
func mustPort(addr string) uint16 {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		panic(fmt.Sprintf("address %q was not checked by Validate: %v", addr, err))
	}
	return ap.Port()
}

// CountryRuleSet builds geoip-<code>.json with a nonmatching placeholder when
// no prefixes are available; an empty condition would match all traffic.
func CountryRuleSet(prefixes []netip.Prefix) []byte {
	cidrs := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		cidrs = append(cidrs, p.String())
	}
	if len(cidrs) == 0 {
		cidrs = []string{noSource}
	}
	raw, _ := json.Marshal(obj{"version": 3, "rules": []obj{{"ip_cidr": cidrs}}})
	return raw
}
