package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/geodata"
)

// Verify the files served by the HTTPS fixture with the real decoder and
// production extraction limits.
func TestGeneratedDatFiles(t *testing.T) {
	for name, size := range sizes {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := generate(dir, size); err != nil {
				t.Fatal(err)
			}
			read := func(file string, wantBytes int) []byte {
				t.Helper()
				raw, err := os.ReadFile(filepath.Join(dir, "data", file))
				if err != nil {
					t.Fatal(err)
				}
				if len(raw) != wantBytes {
					t.Fatalf("%s is %d bytes; want %d", file, len(raw), wantBytes)
				}
				return raw
			}
			want := map[string]bool{"fixture": true}
			sites, err := geodata.ExtractSites(read("geosite.dat", size.GeositeBytes), want, geodata.DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			names := sites["fixture"].Suffix
			if len(names) != size.Domains || names[dnsNames-1] != domain(dnsNames-1) {
				t.Fatalf("geosite payload did not extract the expected %d domains", size.Domains)
			}
			ips, err := geodata.ExtractIPs(read("geoip.dat", size.GeoipBytes), want, geodata.DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			if len(ips["fixture"]) != size.Prefixes {
				t.Fatalf("geoip payload did not extract the expected %d prefixes", size.Prefixes)
			}
		})
	}
}
