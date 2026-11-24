package lists

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Compact sorted suffix lists for large domain sets: Parse reads plain, hosts
// and basic Adblock DNS formats; DomainIndex does the suffix lookup.

// MaxBytes bounds the downloaded text accepted by Parse.
const MaxBytes = 8 << 20

// MaxRules bounds combined block and allow entries in one source.
const MaxRules = 200000

// MaxTotalRules bounds loaded entries across all configured sources.
const MaxTotalRules = 300000

// Parsed holds sorted unique DNS block/allow suffixes and a skipped-entry count.
type Parsed struct {
	Domains []string `json:"domains"`
	Allow   []string `json:"allow"`
	Skipped int      `json:"skipped"`
}

var domainRE = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]*[a-z0-9]$`)

func domain(s string) string {
	e, err := model.ParseEntry(s)
	if err != nil || e.Kind != model.EntryDomain || !domainRE.MatchString(e.Domain) || strings.Contains(e.Domain, "..") {
		return ""
	}
	return e.Domain
}

// Parse accepts plain domains, hosts files, and basic Adblock DNS rules under fixed limits.
func Parse(r io.Reader) (Parsed, error) {
	p := Parsed{}
	lr := &io.LimitedReader{R: r, N: MaxBytes + 1}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 4096), 65536)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
			p.Skipped++
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 && i > 0 && (line[i-1] == ' ' || line[i-1] == '\t') {
			line = strings.TrimSpace(line[:i])
		}
		allow := strings.HasPrefix(line, "@@||")
		if allow {
			line = strings.TrimPrefix(line, "@@")
		}
		if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			line = strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^")
		}
		fields := strings.Fields(line)
		if len(fields) > 1 {
			if a, err := netip.ParseAddr(fields[0]); err == nil && (a.IsUnspecified() || a.IsLoopback()) {
				fields = fields[1:]
			} else {
				p.Skipped++
				continue
			}
		}
		for _, s := range fields {
			d := domain(s)
			if d == "" {
				p.Skipped++
				continue
			}
			if allow {
				p.Allow = append(p.Allow, d)
			} else {
				p.Domains = append(p.Domains, d)
			}
		}
		if len(p.Domains)+len(p.Allow) > MaxRules {
			return Parsed{}, fmt.Errorf("at most %d rules", MaxRules)
		}
	}
	if err := sc.Err(); err != nil {
		return Parsed{}, err
	}
	if lr.N <= 0 {
		return Parsed{}, fmt.Errorf("list exceeds 8 MiB")
	}
	slices.Sort(p.Domains)
	p.Domains = slices.Compact(p.Domains)
	slices.Sort(p.Allow)
	p.Allow = slices.Compact(p.Allow)
	if len(p.Domains) == 0 {
		return Parsed{}, fmt.Errorf("empty or unsupported list (%d skipped)", p.Skipped)
	}
	return p, nil
}

// DomainList is one list of a DomainIndex. Suffix names match themselves and
// their subdomains on label boundaries, Exact names only themselves.
type DomainList struct{ Suffix, Exact []string }

// DomainIndex maps domain names to the lists that hold them. It is a single
// sorted slice with one entry per name and list, so its memory follows the
// lists, and a lookup costs one binary search per label-delimited suffix of
// the name without allocating. It is immutable and safe for concurrent use.
type DomainIndex struct{ entries []domainEntry }

// domainEntry is one name of the list at position list.
type domainEntry struct {
	name  string
	list  int32
	exact bool
}

// NewDomainIndex indexes lists by their position. Names compare in lowercase
// without a trailing dot; empty names are skipped.
func NewDomainIndex(lists []DomainList) DomainIndex {
	n := 0
	for _, l := range lists {
		n += len(l.Suffix) + len(l.Exact)
	}
	entries := make([]domainEntry, 0, n)
	add := func(list int, names []string, exact bool) {
		for _, name := range names {
			if name = normalizeName(name); name != "" {
				entries = append(entries, domainEntry{name: name, list: int32(list), exact: exact})
			}
		}
	}
	for i, l := range lists {
		add(i, l.Suffix, false)
		add(i, l.Exact, true)
	}
	slices.SortFunc(entries, compareEntries)
	return DomainIndex{entries: slices.Compact(entries)}
}

// Each calls yield with the position of every list that holds name, possibly
// more than once, until yield returns false. name may use any letter case and
// end with a dot.
func (x DomainIndex) Each(name string, yield func(list int) bool) {
	name = normalizeName(name)
	for suffix := name; ; {
		i, _ := slices.BinarySearchFunc(x.entries, suffix, compareName)
		for ; i < len(x.entries) && x.entries[i].name == suffix; i++ {
			if e := x.entries[i]; (!e.exact || len(suffix) == len(name)) && !yield(int(e.list)) {
				return
			}
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			return
		}
		suffix = suffix[dot+1:]
	}
}

// Match reports whether any list holds name.
func (x DomainIndex) Match(name string) bool {
	found := false
	x.Each(name, func(int) bool {
		found = true
		return false
	})
	return found
}

func normalizeName(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func compareName(e domainEntry, name string) int { return strings.Compare(e.name, name) }

// compareEntries orders entries by name, then list and kind, so the entries of
// a name are contiguous and duplicates adjacent.
func compareEntries(a, b domainEntry) int {
	kind := func(e domainEntry) int {
		if e.exact {
			return 1
		}
		return 0
	}
	return cmp.Or(strings.Compare(a.name, b.name), cmp.Compare(a.list, b.list), cmp.Compare(kind(a), kind(b)))
}
