// Command providerload generates synthetic provider files and verifies LAN DNS
// responses in the candidate-only provider memory fixture.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	dnsNames    = 4096
	blockedName = "blocked.provider.test"
	blockedIP   = "198.19.0.1"
)

type fixtureSize struct {
	Domains      int `json:"domains"`
	Prefixes     int `json:"prefixes"`
	GeositeBytes int `json:"geosite_bytes"`
	GeoipBytes   int `json:"geoip_bytes"`
}

var sizes = map[string]fixtureSize{
	"real":  {Domains: 20_000, Prefixes: 35_000, GeositeBytes: 10_900_000, GeoipBytes: 16_300_000},
	"limit": {Domains: 100_000, Prefixes: 200_000, GeositeBytes: 16 << 20, GeoipBytes: 16 << 20},
}

func domain(index int) string { return fmt.Sprintf("host-%06d.provider.test", index) }

func answer(index int) netip.Addr {
	return netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index)})
}

func field(b []byte, number protowire.Number, data []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(b, number, protowire.BytesType), data)
}

func sites(count int) []byte {
	category := field(nil, 1, []byte("fixture"))
	var buf [128]byte
	for i := range count {
		entry := protowire.AppendVarint(protowire.AppendTag(buf[:0], 1, protowire.VarintType), 2) // suffix
		category = field(category, 2, field(entry, 2, []byte(domain(i))))
	}
	return category
}

func prefixes(count int) []byte {
	category := field(nil, 1, []byte("fixture"))
	var buf [16]byte
	for i := range count {
		// Leave gaps between /32s so the matcher cannot coalesce the fixture.
		n := 2 * i
		ip := [4]byte{100, 64 + byte(n>>16), byte(n >> 8), byte(n)}
		entry := field(buf[:0], 1, ip[:])
		entry = protowire.AppendVarint(protowire.AppendTag(entry, 2, protowire.VarintType), 32)
		category = field(category, 2, entry)
	}
	return category
}

// dat bounds wire size independently of the number of matching entries.
// The unused protobuf field models bytes that the decoder skips by length.
func dat(category []byte, size int) []byte {
	encoded := field(make([]byte, 0, size), 1, category)
	encoded = protowire.AppendTag(encoded, 15, protowire.BytesType)
	remaining := size - len(encoded)
	payload := remaining - protowire.SizeVarint(uint64(remaining))
	encoded = protowire.AppendVarint(encoded, uint64(payload))
	return encoded[:size]
}

func generate(dir string, size fixtureSize) error {
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(data, "geosite.dat"), dat(sites(size.Domains), size.GeositeBytes), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(data, "geoip.dat"), dat(prefixes(size.Prefixes), size.GeoipBytes), 0o600); err != nil {
		return err
	}
	var hosts strings.Builder
	for i := range dnsNames {
		fmt.Fprintf(&hosts, "%s %s\n", answer(i), domain(i))
	}
	fmt.Fprintf(&hosts, "%s %s\n", blockedIP, blockedName)
	return os.WriteFile(filepath.Join(dir, "hosts"), []byte(hosts.String()), 0o600)
}

type dnsEvidence struct {
	VerifiedNames int              `json:"verified_names"`
	BlockAnswer   string           `json:"block_answer"`
	Tunnels       []tunnelEvidence `json:"tunnels"`
}

// awaitDNSStart lets the controller confirm both sets of active TCP streams
// using daemon stats after warmup, before issuing the measured query schedule.
func awaitDNSStart(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, "dns-ready"), nil, 0o600); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := os.Stat(filepath.Join(dir, "dns-start"))
		if err == nil || !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for two-tunnel readiness check")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func verifyDNS(server, blockAnswer, dir string, targets []string) (dnsEvidence, error) {
	result := dnsEvidence{BlockAnswer: blockAnswer}
	tunnels := make([]*tunnel, 0, len(targets))
	for _, target := range targets {
		t, err := openTunnel(target)
		if err != nil {
			return result, err
		}
		defer t.close()
		tunnels = append(tunnels, t)
	}
	for _, t := range tunnels {
		if err := t.exchange(0); err != nil {
			return result, err
		}
	}
	if err := awaitDNSStart(dir); err != nil {
		return result, err
	}
	client := dns.Client{Timeout: 2 * time.Second}
	conn, err := client.Dial(server)
	if err != nil {
		return result, err
	}
	defer conn.Close()
	for i := range dnsNames {
		if err := checkAnswer(&client, conn, domain(i), answer(i).String()); err != nil {
			return result, err
		}
		result.VerifiedNames++
		if (i+1)%dnsBatch == 0 {
			for _, t := range tunnels {
				if err := t.exchange((i + 1) / dnsBatch); err != nil {
					return result, err
				}
			}
			time.Sleep(40 * time.Millisecond)
		}
	}
	for _, t := range tunnels {
		result.Tunnels = append(result.Tunnels, t.evidence)
	}
	return result, checkAnswer(&client, conn, blockedName, blockAnswer)
}

func checkAnswer(client *dns.Client, conn *dns.Conn, name, address string) error {
	query := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA)
	reply, _, err := client.ExchangeWithConn(query, conn)
	if err != nil {
		return fmt.Errorf("query %s: %w", name, err)
	}
	if reply.Rcode == dns.RcodeSuccess && len(reply.Answer) == 1 {
		if a, ok := reply.Answer[0].(*dns.A); ok && a.Hdr.Name == dns.Fqdn(name) && a.A.String() == address {
			return nil
		}
	}
	return fmt.Errorf("query %s did not return %s: %v", name, address, reply)
}

func main() {
	if len(os.Args) == 4 {
		switch os.Args[1] {
		case "generate":
			size, ok := sizes[os.Args[2]]
			if ok {
				if err := generate(os.Args[3], size); err != nil {
					log.Fatal(err)
				}
				if err := json.NewEncoder(os.Stdout).Encode(size); err != nil {
					log.Fatal(err)
				}
				return
			}
		}
	}
	if len(os.Args) == 7 && os.Args[1] == "dns" {
		result, err := verifyDNS(os.Args[2], os.Args[3], os.Args[4], os.Args[5:])
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			log.Fatal(err)
		}
		return
	}
	log.Fatal("usage: providerload generate real|limit directory or providerload dns server block-answer directory tunnel1 tunnel2")
}
