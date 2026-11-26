package devices

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

const hotspotTestPath = "/rci/show/ip/hotspot"

func TestNameLookupPrefersKeeneticHotspot(t *testing.T) {
	neighbors := map[string]netip.Addr{
		"02:00:00:00:00:aa": netip.MustParseAddr("192.0.2.1"),
		"02:00:00:00:00:bb": netip.MustParseAddr("192.0.2.2"),
		"02:00:00:00:00:cc": netip.MustParseAddr("192.0.2.3"),
		"02:00:00:00:00:dd": netip.MustParseAddr("192.0.2.4"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RequestURI() != hotspotTestPath {
			t.Errorf("unexpected RCI request: %s %s", r.Method, r.URL.RequestURI())
		}
		_, _ = io.WriteString(w, `{"host":[
			{"mac":"02:00:00:00:00:AA","ip":"192.0.2.9","name":"  \u041d\u043e\u0443\u0442\u0431\u0443\u043a  \u2003\u0414\u043e\u043c\u0430  ","hostname":"laptop","interface":{"id":"Bridge0"},"active":true},
			{"mac":"02:00:00:00:00:AA","hostname":"another-hostname"},
			{"mac":"02:00:00:00:00:BB","name":"bad\n","hostname":"printer.local."},
			{"mac":"02:00:00:00:00:CC","name":"bad\u0000name","hostname":"two words"},
			{"mac":"02:00:00:00:00:EE","ip":"192.0.2.4","name":"another-device"},
			{"mac":"invalid","name":"invalid-device"}
		]}`)
	}))
	defer server.Close()
	source := NameResolver{
		Hotspot: func(ctx context.Context) map[string]string {
			return readKeeneticHotspot(ctx, server.URL+hotspotTestPath)
		},
		Leases: func(context.Context) []LeaseName {
			return []LeaseName{
				{MAC: "02:00:00:00:00:aa", IP: neighbors["02:00:00:00:00:aa"], Hostname: "dhcp-laptop"},
				{MAC: "02:00:00:00:00:cc", IP: neighbors["02:00:00:00:00:cc"], Hostname: "dhcp-phone"},
			}
		},
		Reverse: func(_ context.Context, ip netip.Addr) (string, error) {
			if ip != neighbors["02:00:00:00:00:dd"] {
				t.Errorf("unexpected PTR lookup for %s", ip)
			}
			return "speaker.local.", nil
		},
	}
	want := map[string]Name{
		"02:00:00:00:00:aa": {Hostname: "\u041d\u043e\u0443\u0442\u0431\u0443\u043a \u0414\u043e\u043c\u0430", Source: "rci"},
		"02:00:00:00:00:bb": {Hostname: "printer.local", Source: "rci"},
		"02:00:00:00:00:cc": {Hostname: "dhcp-phone", Source: "dhcp"},
		"02:00:00:00:00:dd": {Hostname: "speaker.local", Source: "dns"},
	}
	if got := source.Lookup(t.Context(), neighbors); !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %+v, want %+v", got, want)
	}
}

func TestKeeneticHotspotBoundsAssignedNamesByRunes(t *testing.T) {
	const validMAC, longMAC, placeholderMAC = "02:00:00:00:00:aa", "02:00:00:00:00:bb", "02:00:00:00:00:cc"
	valid := strings.Repeat("\u0410", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"host":[
			{"mac":"`+validMAC+`","name":" `+valid+` "},
			{"mac":"`+longMAC+`","name":"`+valid+`\u0410","hostname":"printer"},
			{"mac":"`+placeholderMAC+`","name":" * ","hostname":"speaker"}
		]}`)
	}))
	defer server.Close()
	want := map[string]string{validMAC: valid, longMAC: "printer", placeholderMAC: "speaker"}
	if got := readKeeneticHotspot(t.Context(), server.URL+hotspotTestPath); !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %+v, want %+v", got, want)
	}
}

func TestNameLookupFallsBackWhenKeeneticHotspotFails(t *testing.T) {
	const valid = `{"host":[{"mac":"02:00:00:00:00:aa","name":"rci-name"}]}`
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "down"},
		{name: "unavailable", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, valid)
		}},
		{name: "oversized", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, valid+strings.Repeat(" ", 1<<20))
		}},
		{name: "invalid JSON", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, valid+"invalid")
		}},
		{name: "redirect", handler: func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != hotspotTestPath {
				t.Error("RCI client followed a redirect")
				_, _ = io.WriteString(w, valid)
				return
			}
			http.Redirect(w, r, "/other", http.StatusFound)
		}},
		{name: "stalled body", handler: func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, valid)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			if tc.handler == nil {
				server.Close()
			}
			const laptop, phone = "02:00:00:00:00:aa", "02:00:00:00:00:bb"
			neighbors := map[string]netip.Addr{laptop: netip.MustParseAddr("192.0.2.1"), phone: netip.MustParseAddr("192.0.2.2")}
			source := NameResolver{
				Hotspot: func(ctx context.Context) map[string]string {
					return readKeeneticHotspot(ctx, server.URL+hotspotTestPath)
				},
				Leases: func(context.Context) []LeaseName {
					return []LeaseName{{MAC: laptop, IP: neighbors[laptop], Hostname: "laptop"}}
				},
				Reverse: func(context.Context, netip.Addr) (string, error) { return "phone.local.", nil },
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			want := map[string]Name{laptop: {Hostname: "laptop", Source: "dhcp"}, phone: {Hostname: "phone.local", Source: "dns"}}
			if got := source.Lookup(ctx, neighbors); !reflect.DeepEqual(got, want) {
				t.Fatalf("names = %+v, want %+v", got, want)
			}
		})
	}
}
