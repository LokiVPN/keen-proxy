package main

import (
	"errors"
	"net/netip"
	"testing"
)

func TestKeeneticOrigin(t *testing.T) {
	yes, no := func() bool { return true }, func() bool { return false }
	lookup := func(prefixes ...string) func(string) ([]netip.Prefix, error) {
		return func(string) ([]netip.Prefix, error) {
			var out []netip.Prefix
			for _, p := range prefixes {
				out = append(out, netip.MustParsePrefix(p))
			}
			return out, nil
		}
	}
	failing := func(string) ([]netip.Prefix, error) { return nil, errors.New("no such interface") }
	for _, tc := range []struct {
		name, flag string
		keenetic   func() bool
		addrs      func(string) ([]netip.Prefix, error)
		want       string
		wantErr    bool
	}{
		{"explicit flag wins", "http://10.0.0.1:81", yes, lookup("192.168.1.1/24"), "http://10.0.0.1:81", false},
		{"explicit flag off Keenetic", "http://10.0.0.1", no, lookup(), "http://10.0.0.1", false},
		{"off disables", "off", yes, lookup("192.168.1.1/24"), "", false},
		{"non-Keenetic is disabled", "", no, lookup("192.168.1.1/24"), "", false},
		{"derived from the interface", "", yes, lookup("fe80::1/64", "203.0.113.5/24", "192.168.1.1/24"), "http://192.168.1.1", false},
		{"no IPv4", "", yes, lookup("fe80::1/64"), "", true},
		{"lookup failure", "", yes, failing, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keeneticOrigin(tc.flag, "br0", tc.keenetic, tc.addrs)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("got %q, %v; want %q, error=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
