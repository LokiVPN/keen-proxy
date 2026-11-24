package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/geodata"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const (
	maxGeoFileBytes = 16 << 20
	geoFileTimeout  = time.Minute
	// geoFileReuse follows Happ, which refreshes geo files at most weekly.
	geoFileReuse = 7 * 24 * time.Hour

	// Apply spends at most applyGeoBudget on geo files and stops
	// applyGeoHeadroom before its own deadline, which activation and saving
	// need; with less than applyGeoMinimum left it skips the downloads.
	// Files that miss Apply are the worker's retries.
	applyGeoBudget   = 20 * time.Second
	applyGeoHeadroom = 15 * time.Second
	applyGeoMinimum  = time.Second

	// Geo files that partial rules lack are downloaded again after
	// rulesRetryFirst, doubling up to rulesRetryMax, without a subscription fetch.
	rulesRetryFirst = time.Minute
	rulesRetryMax   = time.Hour
)

var (
	errGeoRedirect    = errors.New("geo file redirect rejected")
	errGeoDestination = errors.New("geo file destination refused")
)

// rulesSnapshot is the private provider-rules state of the configured source:
// the rules in use, the geo files their data came from and the latest failure.
// A nil snapshot means rules were never evaluated for the source; Built is nil
// when the provider sends none. Snapshots are replaced, never modified, so
// comparing pointers detects a change.
type rulesSnapshot struct {
	Built *compile.ProviderRules `json:"built,omitempty"`
	// Profile is the provider profile Built came from; a geo file retry
	// rebuilds the rules from it.
	Profile *subscription.RoutingProfile `json:"profile,omitempty"`
	Geosite geoFileRecord                `json:"geosite,omitzero"`
	Geoip   geoFileRecord                `json:"geoip,omitzero"`
	Error   string                       `json:"error,omitempty"` // fixed English text
}

// geoFileRecord names the geo file whose data the rules hold. Downloaded is
// zero when the file could not be loaded and the rules hold none of its data.
type geoFileRecord struct {
	URL        string    `json:"url,omitempty"`
	Downloaded time.Time `json:"downloaded,omitzero"`
}

func (f geoFileRecord) loaded() bool { return f.URL == "" || !f.Downloaded.IsZero() }

// complete reports whether the rules hold the data of every geo file they
// need, so they can stand in as the last good rules after a failure.
func (s *rulesSnapshot) complete() bool {
	return s != nil && s.Built != nil && s.Geosite.loaded() && s.Geoip.loaded()
}

// retryable reports whether the rules lack a geo file's data and keep the
// profile to download it again.
func (s *rulesSnapshot) retryable() bool {
	return s != nil && s.Built != nil && s.Profile != nil && !s.complete()
}

// rulesRetryDelay is the wait before the given consecutive geo file retry.
func rulesRetryDelay(failures int) time.Duration {
	return min(rulesRetryFirst<<(min(max(failures, 1), 7)-1), rulesRetryMax)
}

// scheduleRulesRetry follows newly installed rules: rules lacking geo file
// data get another download with a doubling delay; any other rules end the
// series. The subscription's own refresh schedule is not involved.
func (s *appliedSubscription) scheduleRulesRetry(now time.Time) {
	if !s.snapshot.Rules.retryable() {
		s.rulesFailures, s.rulesRetry = 0, time.Time{}
		return
	}
	s.rulesFailures++
	s.rulesRetry = now.Add(rulesRetryDelay(s.rulesFailures))
}

// applyGeoContext bounds the geo downloads of an Apply by applyGeoBudget and
// by Apply's deadline less applyGeoHeadroom. A budget under applyGeoMinimum
// is spent at once: the downloads fail without a request, as on expiry.
func applyGeoContext(ctx context.Context) (context.Context, context.CancelFunc) {
	budget := applyGeoBudget
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline)-applyGeoHeadroom)
	}
	if budget < applyGeoMinimum {
		budget = 0
	}
	return context.WithTimeout(ctx, budget)
}

// finishProviderRulesRetryLocked installs rules rebuilt by a geo file retry
// unless the source, its rules or the settings changed meanwhile. A failed
// activation keeps the previous rules and schedules the next retry.
func (d *Daemon) finishProviderRulesRetryLocked(request *subscriptionRefresh, rules *rulesSnapshot) {
	id := request.source.ID
	state := d.subscriptions.states[id]
	if state.request != request {
		return
	}
	state.request = nil
	if state.snapshot.Rules != request.previous || providerRulesSource(d.cfg) != id {
		d.subscriptions.states[id] = state
		return
	}
	state.snapshot.Rules = rules
	state.scheduleRulesRetry(time.Now())
	before, err := d.activateSubscriptionStateLocked(id, state, !sameProviderRules(request.previous, rules))
	if err != nil {
		state = d.subscriptions.states[id]
		state.request = nil
		state.scheduleRulesRetry(time.Now())
		d.subscriptions.states[id] = state
		d.audit("system", "Provider rules not updated", id, "warn", "provider rules could not be activated or saved")
		return
	}
	d.auditSubscriptionSelectionsLocked(before)
}

// holds reports whether the rules hold the data of url for exactly refs, from
// a download younger than geoFileReuse.
func (s *rulesSnapshot) holds(file geoFileRecord, url, prefix string, refs map[string]bool, now time.Time) bool {
	if s == nil || s.Built == nil || file.URL != url || file.Downloaded.IsZero() {
		return false
	}
	if age := now.Sub(file.Downloaded); age < 0 || age >= geoFileReuse {
		return false
	}
	held := map[string]bool{}
	for _, rule := range s.Built.Rules {
		if ref, ok := strings.CutPrefix(rule.Source, prefix); ok {
			held[ref] = true
		}
	}
	return maps.Equal(held, refs)
}

// keptRules records a failed attempt while the rules in use stay.
func keptRules(previous *rulesSnapshot, failure string) *rulesSnapshot {
	var kept rulesSnapshot
	if previous != nil {
		kept = *previous
	}
	kept.Error = failure
	return &kept
}

// providerRulesSource returns the subscription ID whose rules apply, or "".
func providerRulesSource(cfg *model.Config) string {
	if cfg == nil || cfg.ProviderRules == nil {
		return ""
	}
	return cfg.ProviderRules.Source
}

// syncProviderRules keeps rules only on the configured source, so turning them
// off frees them, and makes that source due now while its rules were never
// evaluated: rules just turned on, or a snapshot saved before rules existed.
func syncProviderRules(cfg *model.Config, s *appliedSubscription) {
	switch {
	case s.source.ID != providerRulesSource(cfg):
		s.snapshot.Rules = nil
		s.rulesFailures, s.rulesRetry = 0, time.Time{}
	case s.snapshot.Rules == nil && s.request == nil:
		s.next = time.Time{}
	}
}

// ProviderRulesState tells what the provider rules of the configured source
// can do, so a page can tell rules that are still loading from rules the
// provider does not offer or that failed.
type ProviderRulesState string

const (
	// ProviderRulesOff: provider rules are not configured.
	ProviderRulesOff ProviderRulesState = "off"
	// ProviderRulesPending: configured, but not evaluated yet.
	ProviderRulesPending ProviderRulesState = "pending"
	// ProviderRulesWithheld: the provider sends no rules: no routing
	// profile, happ://routing/off, or routing-enable withholds them.
	ProviderRulesWithheld ProviderRulesState = "withheld"
	// ProviderRulesReady: every rule is available.
	ProviderRulesReady ProviderRulesState = "ready"
	// ProviderRulesPartial: there are both usable and unavailable rules.
	ProviderRulesPartial ProviderRulesState = "partial"
	// ProviderRulesFailed: evaluation failed and no rules are available;
	// the status's rules_error says why.
	ProviderRulesFailed ProviderRulesState = "failed"
)

// state classifies the rules of the configured source. Last good rules kept
// after a failed update stay ready or partial; their error is only reported.
func (s *rulesSnapshot) state() ProviderRulesState {
	switch {
	case s == nil:
		return ProviderRulesPending
	case s.Built == nil && s.Error == "":
		return ProviderRulesWithheld
	case s.Built == nil:
		return ProviderRulesFailed
	}
	available := 0
	for _, rule := range s.Built.Rules {
		if rule.Unavailable == "" {
			available++
		}
	}
	total := len(s.Built.Rules)
	switch {
	case available == 0 && (total > 0 || s.Error != ""):
		return ProviderRulesFailed
	case available < total:
		return ProviderRulesPartial
	}
	return ProviderRulesReady
}

// ProviderRules returns the rules of the configured source, its settings and
// the rules' state. The rules are empty unless the state is ready or
// partial; the settings are nil only when the state is off. The rules share
// storage with the daemon and must not be modified.
func (d *Daemon) ProviderRules() (compile.ProviderRules, *model.ProviderRulesSettings, ProviderRulesState) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil || d.cfg.ProviderRules == nil {
		return compile.ProviderRules{}, nil, ProviderRulesOff
	}
	settings := *d.cfg.ProviderRules
	settings.Disabled = slices.Clone(settings.Disabled)
	rules := d.subscriptions.states[settings.Source].snapshot.Rules
	state := rules.state()
	if state != ProviderRulesReady && state != ProviderRulesPartial {
		return compile.ProviderRules{}, &settings, state
	}
	return *rules.Built, &settings, state
}

// warnDroppedProviderEntries reports provider entries compile left out when
// rules are activated; watchdog recompilations do not repeat it.
func (d *Daemon) warnDroppedProviderEntries(out compile.Output) {
	if out.DroppedProviderEntries > 0 {
		d.log.Warn("provider rule entries that sing-box cannot use were skipped", "count", out.DroppedProviderEntries)
	}
}

// providerRulesLocked returns the provider rules held for each subscription,
// as compile.Input expects them; compile applies those of the configured
// source. The rules share storage with the snapshots.
func (d *Daemon) providerRulesLocked() map[string]compile.ProviderRules {
	var out map[string]compile.ProviderRules
	for id, state := range d.subscriptions.states {
		if rules := state.snapshot.Rules; rules != nil && rules.Built != nil {
			if out == nil {
				out = map[string]compile.ProviderRules{}
			}
			out[id] = *rules.Built
		}
	}
	return out
}

// evaluateProviderRules builds the rules of one successful fetch of the
// configured source. It downloads geo files and must run without d.mu.
// previous is the source's current state: its data is reused for unchanged
// files, and complete previous rules stay when this attempt fails.
func (d *Daemon) evaluateProviderRules(ctx context.Context, result subscription.Result, previous *rulesSnapshot) *rulesSnapshot {
	profile := result.Routing
	if profile == nil {
		if result.RoutingError == "" {
			return &rulesSnapshot{} // the provider sends no rules
		}
		return keptRules(previous, result.RoutingError)
	}
	var held rulesSnapshot
	if previous != nil {
		held = *previous
	}
	now := time.Now()
	siteRefs, ipRefs := compile.ProviderRuleRefs(profile)
	sites, siteFile, siteFailure := geoFile[geodata.Sites]{
		name: "geosite", url: profile.GeositeURL, refs: siteRefs, extract: geodata.ExtractSites,
		reuse: func(r compile.ProviderRule) geodata.Sites {
			return geodata.Sites{Suffix: r.Suffix, Full: r.Full, Keyword: r.Keyword, Regex: r.Regex}
		},
	}.load(ctx, d, previous, held.Geosite, now)
	ips, ipFile, ipFailure := geoFile[[]netip.Prefix]{
		name: "geoip", url: profile.GeoipURL, refs: ipRefs, extract: geodata.ExtractIPs,
		reuse: func(r compile.ProviderRule) []netip.Prefix {
			prefixes := make([]netip.Prefix, 0, len(r.CIDR))
			for _, value := range r.CIDR {
				if prefix, err := netip.ParsePrefix(value); err == nil {
					prefixes = append(prefixes, prefix)
				}
			}
			return prefixes
		},
	}.load(ctx, d, previous, held.Geoip, now)
	failure := strings.Join(slices.DeleteFunc([]string{siteFailure, ipFailure}, func(s string) bool { return s == "" }), "; ")
	if failure != "" && previous.complete() {
		return keptRules(previous, failure)
	}
	rules := compile.BuildProviderRules(profile, sites, ips, d.countryLookup(profile, ipRefs))
	markUnavailable(&rules, "geosite:", siteFailure)
	markUnavailable(&rules, "geoip:", ipFailure)
	return &rulesSnapshot{Built: &rules, Profile: profile, Geosite: siteFile, Geoip: ipFile, Error: failure}
}

// markUnavailable replaces the builder's generic reason on the rules of a geo
// file that failed to load with that failure.
func markUnavailable(rules *compile.ProviderRules, prefix, failure string) {
	if failure == "" {
		return
	}
	for i := range rules.Rules {
		if strings.HasPrefix(rules.Rules[i].Source, prefix) {
			rules.Rules[i].Unavailable = failure
		}
	}
}

// geoFile is one geo file of a routing profile. reuse recovers the data of
// one reference from a rule built from the same file.
type geoFile[T any] struct {
	name    string // geosite or geoip: the entry prefix and the subject of failures
	url     string
	refs    map[string]bool
	extract func([]byte, map[string]bool, geodata.Limits) (map[string]T, error)
	reuse   func(compile.ProviderRule) T
}

// load returns the file's extracted data, the record of what it holds and a
// fixed failure. Data of an unchanged file comes from the previous rules
// while its download is younger than geoFileReuse. Nil data without a failure
// means the profile needs nothing from the file.
func (g geoFile[T]) load(ctx context.Context, d *Daemon, previous *rulesSnapshot, held geoFileRecord, now time.Time) (map[string]T, geoFileRecord, string) {
	prefix := g.name + ":"
	switch {
	case g.url == "" || len(g.refs) == 0:
		return nil, geoFileRecord{}, ""
	case previous.holds(held, g.url, prefix, g.refs, now):
		data := make(map[string]T, len(g.refs))
		for _, rule := range previous.Built.Rules {
			if ref, ok := strings.CutPrefix(rule.Source, prefix); ok && rule.HasData() {
				data[ref] = g.reuse(rule)
			}
		}
		return data, held, ""
	}
	raw, failure := d.downloadGeoFile(ctx, g.name, g.url)
	if failure != "" {
		return nil, geoFileRecord{URL: g.url}, failure
	}
	data, err := g.extract(raw, g.refs, geodata.DefaultLimits)
	switch {
	case errors.Is(err, geodata.ErrLimit):
		return nil, geoFileRecord{URL: g.url}, g.name + " data exceeds the extraction limit"
	case err != nil:
		return nil, geoFileRecord{URL: g.url}, g.name + " file could not be read"
	}
	return data, geoFileRecord{URL: g.url, Downloaded: now}, ""
}

// downloadGeoFile fetches one geo file directly over the subscription
// transport: HTTPS only, at most maxGeoFileBytes, within geoFileTimeout, and
// only from destinations geoDestination allows. Failures are fixed messages;
// the URL may carry a token and is never shown.
func (d *Daemon) downloadGeoFile(ctx context.Context, name, url string) ([]byte, string) {
	failed := name + " file could not be downloaded"
	tooLarge := name + " file is larger than 16 MiB"
	ctx, cancel := context.WithTimeout(ctx, geoFileTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	transport := geoTransport(d.subscriptions.fetcher.Transport(), d.subscriptions.geoDestination)
	if err != nil || req.URL.Scheme != "https" || transport == nil {
		return nil, failed
	}
	defer transport.CloseIdleConnections()
	req.Header.Set("User-Agent", "KeenProxy/1")
	client := http.Client{Transport: transport, CheckRedirect: geoFileRedirect}
	resp, err := client.Do(req)
	if err != nil {
		return nil, failed
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode != http.StatusOK:
		return nil, failed
	case resp.ContentLength > maxGeoFileBytes:
		return nil, tooLarge
	}
	// A known length is allocated once; MinRead leaves room to detect the end.
	buf := bytes.NewBuffer(make([]byte, 0, max(0, resp.ContentLength)+bytes.MinRead))
	_, err = buf.ReadFrom(io.LimitReader(resp.Body, maxGeoFileBytes+1))
	switch {
	case err != nil:
		return nil, failed
	case buf.Len() > maxGeoFileBytes:
		return nil, tooLarge
	}
	return buf.Bytes(), ""
}

// geoTransport returns base, the subscription's direct transport, dialing
// every connection itself and only to destinations allowed accepts. The
// dialer checks the address it connects to, so names that resolve to the
// LAN and redirect targets are covered as well. It returns nil when base is
// not an *http.Transport, whose dialing cannot be guarded.
func geoTransport(base http.RoundTripper, allowed func(netip.AddrPort) bool) *http.Transport {
	t, ok := base.(*http.Transport)
	if !ok {
		return nil
	}
	t = t.Clone()
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		if ap, err := netip.ParseAddrPort(address); err != nil || !allowed(ap) {
			return errGeoDestination
		}
		return nil
	}}
	t.Proxy, t.DialTLSContext, t.DialContext = nil, nil, dialer.DialContext
	return t
}

// geoFileRedirect follows at most three HTTPS redirects, such as a release
// download, without passing the previous URL on as Referer.
func geoFileRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" || len(via) > 3 {
		return errGeoRedirect
	}
	req.Header.Del("Referer")
	return nil
}

// publicDestination refuses the destinations a provider's geo file URL must
// not reach through the router: the router itself, the local network
// (RFC 1918 and unique local addresses), link-local, unspecified and
// multicast addresses.
func publicDestination(ap netip.AddrPort) bool {
	a := ap.Addr().Unmap()
	return a.IsValid() && !a.IsLoopback() && !a.IsPrivate() && !a.IsLinkLocalUnicast() && !a.IsUnspecified() && !a.IsMulticast()
}

// countryLookup serves built-in country prefixes to the rules of a profile
// without a geoip file. Database reads take d.mu so a reload cannot close a
// reader in use.
func (d *Daemon) countryLookup(profile *subscription.RoutingProfile, tags map[string]bool) func(string) ([]netip.Prefix, bool) {
	if profile.GeoipURL != "" || len(tags) == 0 {
		return nil
	}
	d.mu.Lock()
	prefixes, err := d.geo.set.Prefixes(slices.Collect(maps.Keys(tags)))
	d.mu.Unlock()
	if err != nil {
		return nil
	}
	return func(code string) ([]netip.Prefix, bool) {
		found, ok := prefixes[code]
		return found, ok
	}
}
