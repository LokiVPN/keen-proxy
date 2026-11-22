package stats

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type fakeOut struct {
	adapter.Outbound
	tag string
}

func (f fakeOut) Tag() string { return f.tag }

func TestTrackerCountsAndSamples(t *testing.T) {
	tr := NewTracker()
	client, inbound := net.Pipe()
	defer client.Close()
	meta := adapter.InboundContext{Domain: "YouTube.com", Destination: M.SocksaddrFrom(netip.MustParseAddr("142.250.1.1"), 443)}
	c := tr.RoutedConnection(context.Background(), inbound, meta, nil, fakeOut{tag: "fi"})

	// The device sends 100 bytes (upload) and receives 300 bytes (download).
	go func() { client.Write(make([]byte, 100)); io.ReadFull(client, make([]byte, 300)) }()
	if _, err := io.ReadFull(c, make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(make([]byte, 300)); err != nil {
		t.Fatal(err)
	}

	tr.sample(time.Now())
	snap := tr.Snapshot(true)
	if len(snap.Outbounds) != 1 {
		t.Fatalf("outbounds: %+v", snap.Outbounds)
	}
	o := snap.Outbounds[0]
	if o.Tag != "fi" || o.UpTotal != 100 || o.DownTotal != 300 || o.Active != 1 || o.Unique != 1 {
		t.Errorf("summary: %+v", o)
	}
	if o.Down != 300*8/SampleInterval.Seconds() {
		t.Errorf("speed: %v", o.Down)
	}
	if len(o.Top) != 1 || o.Top[0].Host != "youtube.com" || o.Top[0].Requests != 1 {
		t.Errorf("top: %+v", o.Top)
	}

	c.Close()
	tr.sample(time.Now())
	o = tr.Snapshot(false).Outbounds[0]
	if o.Active != 0 || o.Unique != 0 || o.PeakUniq != 1 || o.Down != 0 {
		t.Errorf("after close: %+v", o)
	}
	hosts, total := tr.Hosts("fi", "tube", 10)
	if total != 1 || len(hosts) != 1 || hosts[0].Down != 300 {
		t.Errorf("hosts: %+v %d", hosts, total)
	}
	if h, _ := tr.Hosts("fi", "nomatch", 10); len(h) != 0 {
		t.Errorf("filter: %+v", h)
	}
}

func TestEvictsOldHosts(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < MaxHosts+10; i++ {
		meta := adapter.InboundContext{Destination: M.SocksaddrFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 80)}
		a, b := net.Pipe()
		tr.RoutedConnection(context.Background(), a, meta, nil, fakeOut{tag: "direct"}).Close()
		b.Close()
	}
	if _, total := tr.Hosts("direct", "", 0); total != MaxHosts {
		t.Errorf("hosts %d, want limit %d", total, MaxHosts)
	}
}

func TestTrackerPrunesSubscriptionHistoryAfterCatalogRotation(t *testing.T) {
	tr := NewTracker()
	recordTrackerHost(tr, "manual", "manual.example")
	previous := ""
	for i := range 64 {
		next := fmt.Sprintf("subscription:provider:%032x", i)
		tr.RetainSubscriptionNodes([]string{next})
		recordTrackerHost(tr, next, "site.example")
		tr.sample(time.Now())

		snapshot := tr.Snapshot(true)
		if len(snapshot.Outbounds) != 2 || snapshot.Outbounds[0].Tag != "manual" || snapshot.Outbounds[1].Tag != next {
			t.Fatalf("rotation %d retained unexpected outbounds: %+v", i, snapshot.Outbounds)
		}
		if _, total := tr.Hosts(previous, "", 0); total != 0 {
			t.Fatalf("retired tag retained %d hosts", total)
		}
		previous = next
	}
	tr.RetainSubscriptionNodes(nil)
	if snapshot := tr.Snapshot(false); len(snapshot.Outbounds) != 1 || snapshot.Outbounds[0].Tag != "manual" {
		t.Fatalf("removing the catalog should leave only the manual outbound: %+v", snapshot.Outbounds)
	}
}

func TestTrackerRetainsOpenFlowsOnRetiredSubscriptionNode(t *testing.T) {
	const tag = "subscription:provider:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tr := NewTracker()
	tr.RetainSubscriptionNodes([]string{tag})
	device, inbound := net.Pipe()
	defer device.Close()
	open := tr.RoutedConnection(context.Background(), inbound, adapter.InboundContext{Domain: "site.example"}, nil, fakeOut{tag: tag})
	defer open.Close()
	tr.RetainSubscriptionNodes(nil)

	// A route can already have selected the retired node when the catalog changes.
	otherDevice, otherInbound := net.Pipe()
	defer otherDevice.Close()
	late := tr.RoutedConnection(context.Background(), otherInbound, adapter.InboundContext{Domain: "other.example"}, nil, fakeOut{tag: tag})
	defer late.Close()
	go func() { _, _ = otherDevice.Write([]byte("payload")) }()
	if _, err := io.ReadFull(late, make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	_ = open.Close()
	tr.sample(time.Now())

	snapshot := tr.Snapshot(true)
	if len(snapshot.Outbounds) != 1 || snapshot.Outbounds[0].Tag != tag ||
		snapshot.Outbounds[0].Active != 1 || snapshot.Outbounds[0].UpTotal != 7 {
		t.Fatalf("retired node lost an active flow or its counters: %+v", snapshot.Outbounds)
	}
	_ = late.Close()
	if snapshot := tr.Snapshot(true); len(snapshot.Outbounds) != 0 {
		t.Fatalf("retired node still has history after its last flow closed: %+v", snapshot.Outbounds)
	}

	recordTrackerHost(tr, tag, "late.example")
	if _, total := tr.Hosts(tag, "", 0); total != 0 {
		t.Fatalf("late flow recreated history for a retired subscription node: %d hosts", total)
	}
}

func TestTrackerBoundsHostsPerSubscriptionNode(t *testing.T) {
	tr := NewTracker()
	tags := make([]string, 256)
	for i := range tags {
		tags[i] = fmt.Sprintf("subscription:provider:%032x", i)
	}
	tr.RetainSubscriptionNodes(tags)
	for _, tag := range tags {
		for i := range 40 {
			recordTrackerHost(tr, tag, fmt.Sprintf("site%d.example", i))
		}
		hosts, total := tr.Hosts(tag, "", 0)
		if total != 32 || !slices.ContainsFunc(hosts, func(host Host) bool { return host.Host == "site39.example" }) {
			t.Fatalf("node %q retained %d hosts or discarded its newest host", tag, total)
		}
	}
}

func recordTrackerHost(tr *Tracker, tag, domain string) {
	device, inbound := net.Pipe()
	_ = tr.RoutedConnection(context.Background(), inbound, adapter.InboundContext{Domain: domain}, nil, fakeOut{tag: tag}).Close()
	_ = device.Close()
}

// The panel previews the ranking and offers the rest only when total says more
// hosts match the current filter.
func TestHostsTotalCountsFilteredMatchesBeforeLimit(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 15; i++ {
		name := "video" + strconv.Itoa(i) + ".example"
		if i >= 12 {
			name = "mail" + strconv.Itoa(i) + ".example"
		}
		tr.open(adapter.InboundContext{Domain: name}, fakeOut{tag: "fi"}).host.down.Store(int64(i))
	}
	list, total := tr.Hosts("fi", "VIDEO", 10)
	if total != 12 || len(list) != 10 || list[0].Host != "video11.example" || list[9].Host != "video2.example" {
		t.Fatalf("preview: total %d, %+v", total, list)
	}
	if all, total := tr.Hosts("fi", "", 15); total != 15 || len(all) != 15 {
		t.Fatalf("all: total %d, %d rows", total, len(all))
	}
}
