package lists

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestParseFormats(t *testing.T) {
	p, err := Parse(strings.NewReader("# test\n0.0.0.0 ads.test tracker.test\n||bad.test^\n@@||safe.bad.test^\nsite.test/path\n"))
	if err != nil || len(p.Domains) != 3 || len(p.Allow) != 1 || p.Skipped != 1 {
		t.Fatal(p, err)
	}
}

func TestCosmeticRuleDoesNotBlockWholeSite(t *testing.T) {
	p, err := Parse(strings.NewReader("ads.test\nexample.org##.sponsor\nexample.net#@#.ad\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Domains) != 1 || p.Skipped != 2 {
		t.Fatal(p)
	}
}

func TestSuffixMatch(t *testing.T) {
	p, err := Parse(strings.NewReader("ads.test\n@@||safe.ads.test^\n"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := NewDomainIndex([]DomainList{{Suffix: p.Domains}})
	for name, want := range map[string]bool{"ads.test": true, "Sub.Ads.Test.": true, "other.test": false} {
		if got := blocks.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
	if !NewDomainIndex([]DomainList{{Suffix: p.Allow}}).Match("x.safe.ads.test") {
		t.Error("allow suffix not matched")
	}
}

// The index reports every list holding a name: suffix names also match their
// subdomains on label boundaries, exact names only themselves.
func TestDomainIndexLists(t *testing.T) {
	x := NewDomainIndex([]DomainList{
		{Suffix: []string{"example.com"}},
		{Suffix: []string{"Video.Example.COM."}, Exact: []string{"exact.example.com", ""}},
		{Exact: []string{"com"}},
		{},
	})
	for name, want := range map[string][]int{
		"example.com":           {0},
		"WWW.Example.Com.":      {0},
		"video.example.com":     {0, 1},
		"cdn.video.example.com": {0, 1},
		"exact.example.com":     {0, 1},
		"www.exact.example.com": {0},
		"com":                   {2},
		"www.com":               nil,
		"notexample.com":        nil,
		"":                      nil,
	} {
		var got []int
		x.Each(name, func(list int) bool {
			if !slices.Contains(got, list) {
				got = append(got, list)
			}
			return true
		})
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("lists of %q = %v, want %v", name, got, want)
		}
		if x.Match(name) != (len(want) > 0) {
			t.Errorf("Match(%q) = %v", name, !(len(want) > 0))
		}
	}
	calls := 0
	x.Each("cdn.video.example.com", func(int) bool { calls++; return false })
	if calls != 1 {
		t.Errorf("Each went on after a stop: %d calls", calls)
	}
}

// Lookups do not allocate, however long the lists are.
func TestDomainIndexLookupsDoNotAllocate(t *testing.T) {
	names := make([]string, 100000)
	for i := range names {
		names[i] = fmt.Sprintf("%06d.tracker.test", i)
	}
	x := NewDomainIndex([]DomainList{{Suffix: names}, {Exact: names[:10]}})
	for _, name := range []string{"www.000042.tracker.test.", "000007.tracker.test", "unrelated.example"} {
		lookup := func() {
			x.Match(name)
			x.Each(name, func(int) bool { return true })
		}
		if n := testing.AllocsPerRun(100, lookup); n != 0 {
			t.Errorf("%s: %v allocations per lookup", name, n)
		}
	}
}
