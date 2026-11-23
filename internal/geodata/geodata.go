// Package geodata extracts referenced categories from v2ray geosite.dat and
// geoip.dat files. The files are protobuf messages; this package decodes them
// with protowire and skips unwanted entries by length, so a multi-megabyte
// file costs one linear pass and allocates only for what was requested.
//
// Wire layout relied upon (unknown fields are skipped at every level):
//
//	GeoSiteList { repeated GeoSite entry = 1 }
//	GeoSite     { string country_code = 1; repeated Domain domain = 2 }
//	Domain      { Type type = 1 (0 plain, 1 regex, 2 domain, 3 full); string value = 2; repeated Attribute attribute = 3 }
//	Attribute   { string key = 1 }
//	GeoIPList   { repeated GeoIP entry = 1 }
//	GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3 }
//	CIDR        { bytes ip = 1 (4 or 16 bytes); uint32 prefix = 2 }
package geodata

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// Sites holds the domain matchers of one geosite reference, by match kind.
type Sites struct{ Suffix, Full, Keyword, Regex []string }

// Limits bounds the total number of extracted domains and prefixes so a
// hostile or corrupt file cannot exhaust memory.
type Limits struct{ Domains, Prefixes int }

// DefaultLimits is generous for real provider data (tens of thousands of
// prefixes) while keeping extraction memory bounded.
var DefaultLimits = Limits{Domains: 100000, Prefixes: 200000}

var errMalformed = errors.New("malformed geodata file")

// walk calls fn for every field of the protobuf message b. For length-delimited
// fields v is the payload; for varints n is the value. Other wire types are
// skipped.
func walk(b []byte, fn func(num protowire.Number, v []byte, n uint64) error) error {
	for len(b) > 0 {
		num, typ, tl := protowire.ConsumeTag(b)
		if tl < 0 {
			return errMalformed
		}
		b = b[tl:]
		var v []byte
		var n uint64
		var l int
		switch typ {
		case protowire.BytesType:
			v, l = protowire.ConsumeBytes(b)
		case protowire.VarintType:
			n, l = protowire.ConsumeVarint(b)
		default:
			l = protowire.ConsumeFieldValue(num, typ, b)
		}
		if l < 0 {
			return errMalformed
		}
		b = b[l:]
		if typ == protowire.BytesType || typ == protowire.VarintType {
			if err := fn(num, v, n); err != nil {
				return err
			}
		}
	}
	return nil
}

// entryCode returns the lower-cased country_code of a GeoSite/GeoIP entry.
func entryCode(entry []byte) (string, error) {
	code := ""
	err := walk(entry, func(num protowire.Number, v []byte, _ uint64) error {
		if num == 1 {
			code = strings.ToLower(string(v))
		}
		return nil
	})
	return code, err
}

// ref is one requested geosite reference: key as written, attr lower-cased.
type ref struct{ key, attr string }

func indexRefs(want map[string]bool) map[string][]ref {
	idx := map[string][]ref{}
	for k, ok := range want {
		if !ok {
			continue
		}
		cat, attr, _ := strings.Cut(k, "@")
		cat = strings.ToLower(cat)
		idx[cat] = append(idx[cat], ref{key: k, attr: strings.ToLower(attr)})
	}
	return idx
}

// ExtractSites returns the domains of the requested geosite references, keyed
// by the reference string. want holds "category" or "category@attr"; the
// category matches case-insensitively and @attr keeps only domains carrying an
// attribute with that key. References absent from the file are absent from the
// result. An empty want returns an empty map without scanning data. Exceeding
// l.Domains in total is an error.
func ExtractSites(data []byte, want map[string]bool, l Limits) (map[string]Sites, error) {
	out := map[string]Sites{}
	idx := indexRefs(want)
	if len(idx) == 0 {
		return out, nil
	}
	total := 0
	err := walk(data, func(num protowire.Number, entry []byte, _ uint64) error {
		if num != 1 {
			return nil
		}
		code, err := entryCode(entry)
		if err != nil {
			return err
		}
		refs := idx[code]
		if len(refs) == 0 {
			return nil
		}
		for _, r := range refs {
			if _, ok := out[r.key]; !ok {
				out[r.key] = Sites{}
			}
		}
		return walk(entry, func(num protowire.Number, dom []byte, _ uint64) error {
			if num != 2 {
				return nil
			}
			typ, value, attrs, err := decodeDomain(dom)
			if err != nil {
				return err
			}
			for _, r := range refs {
				if r.attr != "" && !attrs[r.attr] {
					continue
				}
				if total++; total > l.Domains {
					return fmt.Errorf("geosite domain limit %d exceeded in category %q", l.Domains, code)
				}
				s := out[r.key]
				switch typ {
				case 0:
					s.Keyword = append(s.Keyword, value)
				case 1:
					s.Regex = append(s.Regex, value)
				case 2:
					s.Suffix = append(s.Suffix, value)
				case 3:
					s.Full = append(s.Full, value)
				}
				out[r.key] = s
			}
			return nil
		})
	})
	if err != nil {
		return nil, wrapErr("geosite", err)
	}
	return out, nil
}

func decodeDomain(b []byte) (typ uint64, value string, attrs map[string]bool, err error) {
	attrs = map[string]bool{}
	err = walk(b, func(num protowire.Number, v []byte, n uint64) error {
		switch num {
		case 1:
			typ = n
		case 2:
			value = string(v)
		case 3:
			return walk(v, func(num protowire.Number, k []byte, _ uint64) error {
				if num == 1 {
					attrs[strings.ToLower(string(k))] = true
				}
				return nil
			})
		}
		return nil
	})
	return
}

// ExtractIPs returns the prefixes of the requested geoip tags (matched
// case-insensitively), keyed by the tag as written in want. Tags absent from
// the file or marked reverse_match are absent from the result. An empty want
// returns an empty map without scanning data. Exceeding l.Prefixes in total is
// an error; a CIDR with a bad address length or prefix is a malformed file.
func ExtractIPs(data []byte, want map[string]bool, l Limits) (map[string][]netip.Prefix, error) {
	out := map[string][]netip.Prefix{}
	idx := map[string][]string{}
	for k, ok := range want {
		if ok {
			c := strings.ToLower(k)
			idx[c] = append(idx[c], k)
		}
	}
	if len(idx) == 0 {
		return out, nil
	}
	total := 0
	err := walk(data, func(num protowire.Number, entry []byte, _ uint64) error {
		if num != 1 {
			return nil
		}
		code, err := entryCode(entry)
		if err != nil {
			return err
		}
		keys := idx[code]
		if len(keys) == 0 {
			return nil
		}
		var prefixes []netip.Prefix
		reverse := false
		err = walk(entry, func(num protowire.Number, c []byte, n uint64) error {
			switch num {
			case 3:
				reverse = n != 0
			case 2:
				p, err := decodeCIDR(c)
				if err != nil {
					return err
				}
				if total += len(keys); total > l.Prefixes {
					return fmt.Errorf("geoip prefix limit %d exceeded in tag %q", l.Prefixes, code)
				}
				prefixes = append(prefixes, p)
			}
			return nil
		})
		if err != nil || reverse {
			return err
		}
		for _, k := range keys {
			out[k] = append(out[k], prefixes...)
		}
		return nil
	})
	if err != nil {
		return nil, wrapErr("geoip", err)
	}
	return out, nil
}

func decodeCIDR(b []byte) (netip.Prefix, error) {
	var ip []byte
	var bits uint64
	if err := walk(b, func(num protowire.Number, v []byte, n uint64) error {
		switch num {
		case 1:
			ip = v
		case 2:
			bits = n
		}
		return nil
	}); err != nil {
		return netip.Prefix{}, err
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || bits > uint64(addr.BitLen()) {
		return netip.Prefix{}, errMalformed
	}
	return netip.PrefixFrom(addr, int(bits)).Masked(), nil
}

// wrapErr prefixes errors with the file kind unless they already name a limit.
func wrapErr(kind string, err error) error {
	if errors.Is(err, errMalformed) {
		return fmt.Errorf("%s: %w", kind, err)
	}
	return err
}
