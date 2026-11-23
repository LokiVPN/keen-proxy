package geodata

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func bytesField(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func varintField(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

type dom struct {
	typ   uint64
	value string
	attrs []string
}

func siteEntry(code string, doms ...dom) []byte {
	e := bytesField(nil, 1, []byte(code))
	for _, d := range doms {
		var m []byte
		m = varintField(m, 1, d.typ)
		m = bytesField(m, 2, []byte(d.value))
		for _, a := range d.attrs {
			attr := bytesField(nil, 1, []byte(a))
			attr = varintField(attr, 2, 1) // bool_value, ignored
			m = bytesField(m, 3, attr)
		}
		e = bytesField(e, 2, m)
	}
	e = varintField(e, 9, 7) // unknown field must be skipped
	return e
}

func siteList(entries ...[]byte) []byte {
	var b []byte
	for _, e := range entries {
		b = bytesField(b, 1, e)
	}
	return b
}

func cidr(ip []byte, bits uint64) []byte {
	c := bytesField(nil, 1, ip)
	return varintField(c, 2, bits)
}

func ipEntry(code string, reverse bool, cidrs ...[]byte) []byte {
	e := bytesField(nil, 1, []byte(code))
	for _, c := range cidrs {
		e = bytesField(e, 2, c)
	}
	if reverse {
		e = varintField(e, 3, 1)
	}
	return e
}

func ipList(entries ...[]byte) []byte {
	var b []byte
	for _, e := range entries {
		b = bytesField(b, 1, e)
	}
	return b
}

func TestExtractSites(t *testing.T) {
	data := siteList(
		siteEntry("CATEGORY-ADS", dom{0, "adkw", nil}, dom{1, `^ad\d+$`, nil}, dom{2, "ads.example", nil}, dom{3, "full.example", nil}),
		siteEntry("GOOGLE", dom{2, "google.com", nil}, dom{2, "google.cn", []string{"cn"}}, dom{3, "x.google.com", []string{"CN", "ads"}}),
		siteEntry("unwanted", dom{2, "nope.example", nil}),
	)
	got, err := ExtractSites(data, map[string]bool{"category-ads": true, "google": true, "google@cn": true, "missing": true}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Sites{
		"category-ads": {Keyword: []string{"adkw"}, Regex: []string{`^ad\d+$`}, Suffix: []string{"ads.example"}, Full: []string{"full.example"}},
		"google":       {Suffix: []string{"google.com", "google.cn"}, Full: []string{"x.google.com"}},
		"google@cn":    {Suffix: []string{"google.cn"}, Full: []string{"x.google.com"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestExtractSitesEmptyWantDoesNotScan(t *testing.T) {
	got, err := ExtractSites([]byte{0xff, 0xff}, nil, DefaultLimits)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestExtractSitesLimit(t *testing.T) {
	data := siteList(siteEntry("a", dom{2, "a.example", nil}, dom{2, "b.example", nil}))
	_, err := ExtractSites(data, map[string]bool{"a": true}, Limits{Domains: 1, Prefixes: 10})
	if err == nil || !strings.Contains(err.Error(), "domain limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestExtractSitesMalformed(t *testing.T) {
	data := siteList(siteEntry("a", dom{2, "a.example", nil}))
	for _, cut := range []int{1, len(data) / 2, len(data) - 1} {
		if _, err := ExtractSites(data[:cut], map[string]bool{"a": true}, DefaultLimits); err == nil {
			t.Errorf("cut %d: want error", cut)
		}
	}
}

func TestExtractIPs(t *testing.T) {
	data := ipList(
		ipEntry("DIRECT", false,
			cidr([]byte{10, 1, 2, 3}, 8),
			cidr(netip.MustParseAddr("2001:db8::1").AsSlice(), 32)),
		ipEntry("rev", true, cidr([]byte{1, 1, 1, 0}, 24)),
		ipEntry("other", false, cidr([]byte{2, 2, 2, 0}, 24)),
	)
	got, err := ExtractIPs(data, map[string]bool{"direct": true, "rev": true, "missing": true}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]netip.Prefix{
		"direct": {netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExtractIPsLimitAndMalformed(t *testing.T) {
	two := ipList(ipEntry("a", false, cidr([]byte{1, 0, 0, 0}, 8), cidr([]byte{2, 0, 0, 0}, 8)))
	if _, err := ExtractIPs(two, map[string]bool{"a": true}, Limits{Domains: 10, Prefixes: 1}); err == nil || !strings.Contains(err.Error(), "prefix limit") {
		t.Fatalf("err = %v", err)
	}
	bad := [][]byte{
		ipList(ipEntry("a", false, cidr([]byte{1, 2, 3}, 8))),
		ipList(ipEntry("a", false, cidr([]byte{1, 2, 3, 4}, 33))),
		ipList(ipEntry("a", false, cidr(make([]byte, 16), 129))),
	}
	for i, d := range bad {
		if _, err := ExtractIPs(d, map[string]bool{"a": true}, DefaultLimits); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
	if _, err := ExtractIPs(two[:len(two)-2], map[string]bool{"a": true}, DefaultLimits); err == nil {
		t.Error("truncated: want error")
	}
	if got, err := ExtractIPs(nil, nil, DefaultLimits); err != nil || len(got) != 0 {
		t.Errorf("empty want: %v %v", got, err)
	}
}
