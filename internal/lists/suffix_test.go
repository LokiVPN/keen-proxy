package lists

import (
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
	for name, want := range map[string]bool{"ads.test": true, "Sub.Ads.Test.": true, "other.test": false} {
		if got := matches(p.Domains, name); got != want {
			t.Errorf("matches(%q) = %v, want %v", name, got, want)
		}
	}
	if !matches(p.Allow, "x.safe.ads.test") {
		t.Error("allow suffix not matched")
	}
}
