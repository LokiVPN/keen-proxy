package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
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
)

var errGeoRedirect = errors.New("geo file redirect rejected")

// rulesSnapshot is the private provider-rules state of the configured source:
// the rules in use, the geo files their data came from and the latest failure.
// A nil snapshot means rules were never evaluated for the source; Built is nil
// when the provider sends none. Snapshots are replaced, never modified, so
// comparing pointers detects a change.
type rulesSnapshot struct {
	Built   *compile.ProviderRules `json:"built,omitempty"`
	Geosite geoFileRecord          `json:"geosite,omitzero"`
	Geoip   geoFileRecord          `json:"geoip,omitzero"`
	Error   string                 `json:"error,omitempty"` // fixed English text
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
	case s.snapshot.Rules == nil && s.request == nil:
		s.next = time.Time{}
	}
}

// ProviderRules returns the rules of the configured source and its settings.
// ok is false when provider rules are off or none are available. The rules
// share storage with the daemon and must not be modified.
func (d *Daemon) ProviderRules() (compile.ProviderRules, *model.ProviderRulesSettings, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil || d.cfg.ProviderRules == nil {
		return compile.ProviderRules{}, nil, false
	}
	settings := *d.cfg.ProviderRules
	settings.Disabled = slices.Clone(settings.Disabled)
	rules := d.subscriptions.states[settings.Source].snapshot.Rules
	if rules == nil || rules.Built == nil {
		return compile.ProviderRules{}, &settings, false
	}
	return *rules.Built, &settings, true
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
	return &rulesSnapshot{Built: &rules, Geosite: siteFile, Geoip: ipFile, Error: failure}
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
			if ref, ok := strings.CutPrefix(rule.Source, prefix); ok && rule.Unavailable == "" {
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
// transport: HTTPS only, at most maxGeoFileBytes, within geoFileTimeout.
// Failures are fixed messages; the URL may carry a token and is never shown.
func (d *Daemon) downloadGeoFile(ctx context.Context, name, url string) ([]byte, string) {
	failed := name + " file could not be downloaded"
	tooLarge := name + " file is larger than 16 MiB"
	ctx, cancel := context.WithTimeout(ctx, geoFileTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil || req.URL.Scheme != "https" {
		return nil, failed
	}
	req.Header.Set("User-Agent", "KeenProxy/1")
	client := http.Client{Transport: d.subscriptions.fetcher.Transport(), CheckRedirect: geoFileRedirect}
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

// geoFileRedirect follows at most three HTTPS redirects, such as a release
// download, without passing the previous URL on as Referer.
func geoFileRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" || len(via) > 3 {
		return errGeoRedirect
	}
	req.Header.Del("Referer")
	return nil
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
