package domaincache

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func answer(lines ...string) *dns.Msg {
	m := new(dns.Msg)
	for _, s := range lines {
		r, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, r)
	}
	return m
}

func TestObserveCNAMEExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(func() time.Time { return now })
	c.Observe("www.example.com", answer("www.example.com. 10 IN CNAME cdn.example.net.", "cdn.example.net. 60 IN A 203.0.113.1", "unrelated.test. 90 IN A 203.0.113.2"), "observed")
	r := c.Snapshot(nil)
	if len(r) != 1 || len(r[0].Addresses) != 1 || r[0].Addresses[0].IP != "203.0.113.1" || !r[0].Addresses[0].ExpiresAt.Equal(now.Add(10*time.Second)) {
		t.Fatalf("%+v", r)
	}
	c.SetError("www.example.com", "timeout")
	now = now.Add(11 * time.Second)
	if r = c.Snapshot(nil); len(r[0].Addresses) != 0 || r[0].Error != "timeout" {
		t.Fatalf("%+v", r)
	}
}

func TestZeroTTLAndRefresh(t *testing.T) {
	c := New(time.Now)
	c.Observe("example.com", answer("example.com. 60 IN A 203.0.113.1"), "manual")
	c.Observe("example.com", answer("example.com. 0 IN A 203.0.113.2"), "manual")
	if len(c.Snapshot(nil)[0].Addresses) != 0 {
		t.Fatal("zero TTL retained")
	}
}

func TestLimitsAndEviction(t *testing.T) {
	c := New(time.Now)
	m := answer()
	for i := 1; i < 40; i++ {
		r, _ := dns.NewRR(fmt.Sprintf("example.com. 60 IN A 203.0.113.%d", i))
		m.Answer = append(m.Answer, r)
	}
	c.Observe("example.com", m, "manual")
	if len(c.Snapshot(nil)[0].Addresses) != 32 || !c.Snapshot(nil)[0].Limited {
		t.Fatal("address limit")
	}
	for i := 0; i < 4100; i++ {
		c.SetError(fmt.Sprintf("%d.example.com", i), "timeout")
	}
	if len(c.Snapshot(nil)) != 4096 {
		t.Fatal("name limit")
	}
}

func TestObserveConcurrent(t *testing.T) {
	c := New(time.Now)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				c.Observe("example.com", answer("example.com. 60 IN A 203.0.113.1"), "observed")
				c.Snapshot(nil)
				c.Prune()
			}
		}()
	}
	wg.Wait()
}

func TestCNAMECycleIsNotAnAddress(t *testing.T) {
	c := New(time.Now)
	c.Observe("a.test", answer("a.test. 60 IN CNAME b.test.", "b.test. 60 IN CNAME a.test.", "a.test. 60 IN A 203.0.113.1"), "observed")
	if len(c.Snapshot(nil)[0].Addresses) != 0 {
		t.Fatal("cyclic answer learned an IP")
	}
}

func TestInvalidSpareCNAMEKeepsLastValidAnswerUntilExpiry(t *testing.T) {
	var chain []string
	for i := range 16 {
		chain = append(chain, fmt.Sprintf("hop%d.test. 60 IN CNAME hop%d.test.", i, i+1))
	}
	chain = append(chain, "hop16.test. 60 IN A 203.0.113.2")
	for _, tc := range []struct {
		name    string
		invalid *dns.Msg
	}{
		{"cycle", answer("hop0.test. 60 IN CNAME hop1.test.", "hop1.test. 60 IN CNAME hop0.test.")},
		{"too many hops", answer(chain...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			c := New(func() time.Time { return now })
			c.SetRetentionPolicy(func(string) bool { return false }, nil)
			c.Observe("hop0.test", answer("hop0.test. 40 IN A 203.0.113.1"), "observed")
			now = now.Add(10 * time.Second)
			c.Observe("hop0.test", tc.invalid, "observed")
			held, _ := c.Addresses()
			if got := held["hop0.test"]; !slices.Equal(got, []string{"203.0.113.1"}) {
				t.Errorf("invalid CNAME replaced the last valid address: %v", got)
			}
			now = now.Add(30 * time.Second)
			if got := c.Snapshot(nil); len(got) != 0 {
				t.Errorf("the spare record stayed past the original TTL: %+v", got)
			}
		})
	}
}

func TestServiceRefreshDoesNotCountAsObservation(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(func() time.Time { return now })
	m := answer("example.com. 60 IN A 203.0.113.1")
	c.Observe("example.com", m, "observed")
	observed := now
	now = now.Add(time.Minute)
	c.Observe("example.com", m, "resolved")
	r := c.Snapshot(nil)[0]
	if !r.ObservedAt.Equal(observed) || !r.CheckedAt.Equal(now) {
		t.Fatal(r)
	}
}

// Spare records hold answers nobody refreshes: they leave once their
// addresses expire, and an answer without an address is not kept for them.
// Other records keep their name and attempt history.
func TestSpareRecordsLeaveWhenTheirAddressesExpire(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(func() time.Time { return now })
	c.SetRetentionPolicy(func(name string) bool { return name == "kept.example" || name == "failed.example" }, nil)
	c.Observe("live.example", answer("live.example. 60 IN A 203.0.113.1"), "observed")
	c.Observe("expired.example", answer("expired.example. 5 IN A 203.0.113.2"), "observed")
	c.Observe("kept.example", answer("kept.example. 5 IN A 203.0.113.3"), "observed")
	c.Observe("empty.example", answer("other.example. 60 IN A 203.0.113.4"), "observed")
	c.Observe("cycle.example", answer("cycle.example. 60 IN CNAME cycle.example."), "observed")
	c.SetError("failed.example", "timeout")
	now = now.Add(10 * time.Second)
	var names []string
	for _, r := range c.Snapshot(nil) {
		names = append(names, r.Name)
	}
	if !slices.Equal(names, []string{"failed.example", "kept.example", "live.example"}) {
		t.Errorf("records left: %v", names)
	}
}

// When the cache is full, spare records give way first, the least recently
// attempted one first, so provider names cannot push out own-list records; a
// spare answer that would need to evict another kind is not kept.
func TestSpareRecordsGiveWayWhenFull(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(func() time.Time { return now })
	c.SetRetentionPolicy(func(name string) bool { return name == "own.example" || name == "new.example" }, nil)
	tick := func() { now = now.Add(time.Millisecond) }
	c.Observe("own.example", answer("own.example. 300 IN A 203.0.113.1"), "observed") // the oldest record
	for i := range maxNames - 1 {
		tick()
		name := fmt.Sprintf("p%d.example", i)
		c.Observe(name, answer(name+". 300 IN A 203.0.113.2"), "observed")
	}
	tick()
	c.Observe("new.example", answer("new.example. 300 IN A 203.0.113.3"), "observed")
	tick()
	c.Observe("next.example", answer("next.example. 300 IN A 203.0.113.4"), "observed")
	held := map[string]bool{}
	for _, r := range c.Snapshot(nil) {
		held[r.Name] = true
	}
	if len(held) != maxNames || !held["own.example"] || !held["new.example"] || !held["next.example"] || held["p0.example"] || held["p1.example"] {
		t.Fatalf("own %v, new %v, next %v, p0 %v, p1 %v, %d names",
			held["own.example"], held["new.example"], held["next.example"], held["p0.example"], held["p1.example"], len(held))
	}

	full := New(func() time.Time { return now })
	full.SetRetentionPolicy(func(name string) bool { return name != "spare.example" }, nil)
	for i := range maxNames {
		name := fmt.Sprintf("o%d.example", i)
		full.Observe(name, answer(name+". 300 IN A 203.0.113.5"), "observed")
	}
	full.Observe("spare.example", answer("spare.example. 300 IN A 203.0.113.6"), "observed")
	if got := full.Snapshot(func(r Record) bool { return r.Name == "spare.example" || r.Name == "o0.example" }); len(got) != 1 || got[0].Name != "o0.example" {
		t.Fatalf("a spare answer evicted an own record: %+v", got)
	}
}

func TestFullCacheEvictionReusesRetentionClassification(t *testing.T) {
	const newcomer = "www.new.provider.example"
	var residentCalls, newcomerCalls int
	retain := func(name string) bool {
		if name == newcomer {
			newcomerCalls++
			return false
		}
		residentCalls++
		return true
	}
	start := time.Unix(1000, 0)
	c := New(func() time.Time { return start })
	c.SetRetentionPolicy(retain, nil)
	for i := range maxNames {
		name := fmt.Sprintf("n%d.a.own.example", i)
		c.Observe(name, answer(name+". 300 IN A 203.0.113.1"), "observed")
	}
	newAnswer := answer(newcomer + ". 300 IN A 203.0.113.2")
	checkOverflow := func(phase string, wantResidents int) {
		t.Helper()
		before := c.Generation()
		c.Observe(newcomer, newAnswer, "observed")
		if residentCalls != wantResidents || newcomerCalls != 1 {
			t.Errorf("%s: matcher called for %d resident names and %d incoming names, want %d and 1",
				phase, residentCalls, newcomerCalls, wantResidents)
		}
		if c.Generation() != before {
			t.Errorf("%s: the provider answer changed an all-own cache", phase)
		}
		residentCalls, newcomerCalls = 0, 0
	}

	residentCalls, newcomerCalls = 0, 0
	checkOverflow("unchanged policy", 0)
	c.Observe("n0.a.own.example", answer("n0.a.own.example. 300 IN A 203.0.113.3"), "observed")
	checkOverflow("after updating an existing answer", 0)

	c.SetRetentionPolicy(retain, nil)
	checkOverflow("after installing a new policy", maxNames)
	checkOverflow("after classifying under the new policy", 0)
}

// The generation changes only when a name gains or loses an unexpired
// address, so a reader can skip work while it stays the same.
func TestGenerationFollowsAddressChanges(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(func() time.Time { return now })
	c.SetRetentionPolicy(func(string) bool { return false }, nil)
	c.Observe("a.example", answer("a.example. 60 IN A 203.0.113.1"), "observed")
	first := c.Generation()
	for _, step := range []struct {
		name    string
		change  func()
		changed bool
	}{
		{"the same answer again", func() { c.Observe("a.example", answer("a.example. 30 IN A 203.0.113.1"), "observed") }, false},
		{"a failed attempt", func() { c.SetError("a.example", "timeout") }, false},
		{"time before any expiry", func() { now = now.Add(20 * time.Second) }, false},
		{"a new address", func() { c.Observe("a.example", answer("a.example. 60 IN A 203.0.113.2"), "observed") }, true},
		{"a new name", func() { c.Observe("b.example", answer("b.example. 5 IN A 203.0.113.3"), "observed") }, true},
		{"an expiry", func() { now = now.Add(6 * time.Second) }, true},
	} {
		step.change()
		next := c.Generation()
		if (next != first) != step.changed {
			t.Fatalf("%s: generation %d -> %d", step.name, first, next)
		}
		first = next
	}
}

// Snapshots share the cache's address slices instead of copying every
// record's, and a later expiry does not change a snapshot already taken.
func TestSnapshotDoesNotCopyAddresses(t *testing.T) {
	now := time.Unix(1000, 0)
	c := New(func() time.Time { return now })
	c.SetRetentionPolicy(func(name string) bool { return name == "n1.example" }, nil)
	for i := range maxNames {
		name := fmt.Sprintf("n%d.example", i)
		c.Observe(name, answer(name+". 60 IN A 203.0.113.1", name+". 60 IN A 203.0.113.2"), "observed")
	}
	if n := testing.AllocsPerRun(10, func() { c.Snapshot(nil) }); n > 1 {
		t.Errorf("a snapshot of %d records cost %v allocations", maxNames, n)
	}
	before := c.Snapshot(func(r Record) bool { return r.Name == "n1.example" })
	now = now.Add(time.Minute)
	after := c.Snapshot(func(r Record) bool { return r.Name == "n1.example" })
	if len(before) != 1 || len(before[0].Addresses) != 2 || len(after) != 1 || len(after[0].Addresses) != 0 {
		t.Fatalf("before %+v, after %+v", before, after)
	}
}
