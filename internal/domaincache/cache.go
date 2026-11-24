// Package domaincache stores bounded, expiring DNS observations. It never
// decides which groups participate in routing; that remains the compiler's job.
package domaincache

import (
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// maxNames bounds the number of names the cache holds.
const maxNames = 4096

// Address stores one IPv4 answer and its effective chain TTL expiration.
type Address struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Record keeps successful answers, latest attempt status, and device-observation time.
type Record struct {
	ObservedAt time.Time `json:"observed_at"`
	Name       string    `json:"name"`
	// Addresses are sorted by IP. The cache replaces the slice on change and
	// never modifies it, so snapshots share it: callers must not modify it.
	Addresses   []Address `json:"addresses"`
	CheckedAt   time.Time `json:"checked_at"`
	AttemptedAt time.Time `json:"attempted_at"`
	Error       string    `json:"error,omitempty"`
	Source      string    `json:"source"`
	Limited     bool      `json:"limited,omitempty"`
	// Spare marks an answer that nobody refreshes, such as one for a provider
	// name: the record gives way to the others when the cache is full and
	// leaves once its addresses expire.
	Spare bool `json:"spare,omitempty"`
}

// Cache synchronizes a bounded set of DNS observations using an injected clock.
type Cache struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[string]Record
	// generation changes whenever a name gains or loses an address, so
	// readers can skip work while it stays the same.
	generation uint64
	// expiry is no later than the earliest address expiry, and zero while no
	// address is held: expired addresses are pruned only once it has passed.
	expiry time.Time
}

// New creates an empty cache whose expiration decisions use now.
func New(now func() time.Time) *Cache { return &Cache{now: now, records: map[string]Record{}} }

// Normalize trims whitespace and one trailing dot, then lowercases the DNS name.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// Reclassify updates eviction priority and expiry retention in one pass.
// isSpare runs under the cache lock and must not use the cache.
func (c *Cache) Reclassify(isSpare func(name string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, r := range c.records {
		if spare := isSpare(name); spare != r.Spare {
			r.Spare = spare
			c.records[name] = r
		}
	}
}

// put stores r; the caller holds mu. A new name at the limit first evicts
// the least recently attempted spare record, or, for a record that is not
// spare and without spare records, the least recently attempted record. A
// spare record is dropped rather than evict another kind.
func (c *Cache) put(r Record) {
	old, exists := c.records[r.Name]
	if !exists && len(c.records) >= maxNames {
		var victim string
		var oldest Record
		for name, v := range c.records {
			if victim == "" || (v.Spare && !oldest.Spare) || (v.Spare == oldest.Spare && v.AttemptedAt.Before(oldest.AttemptedAt)) {
				victim, oldest = name, v
			}
		}
		if r.Spare && !oldest.Spare {
			return
		}
		c.removeLocked(victim)
	}
	if !sameIPs(old.Addresses, r.Addresses) {
		c.generation++
	}
	c.records[r.Name] = r
	c.expiry = earliestExpiry(c.expiry, r.Addresses)
}

// removeLocked deletes a record; the caller holds mu.
func (c *Cache) removeLocked(name string) {
	if len(c.records[name].Addresses) > 0 {
		c.generation++
	}
	delete(c.records, name)
}

// sameIPs reports whether two sorted address lists hold the same IPs.
func sameIPs(a, b []Address) bool {
	return slices.EqualFunc(a, b, func(x, y Address) bool { return x.IP == y.IP })
}

// earliestExpiry returns the earlier of at and the first expiry in addrs;
// a zero time means none.
func earliestExpiry(at time.Time, addrs []Address) time.Time {
	for _, a := range addrs {
		if at.IsZero() || a.ExpiresAt.Before(at) {
			at = a.ExpiresAt
		}
	}
	return at
}

// Observe retains only the question's A/CNAME chain, bounded by 32 IPs and the shortest TTL.
// Only device observations advance ObservedAt; service refreshes preserve it.
// spare marks the record as one nobody refreshes; a spare answer without an
// address is not kept.
func (c *Cache) Observe(name string, m *dns.Msg, source string, spare bool) {
	if m == nil || m.Rcode != dns.RcodeSuccess {
		return
	}
	name = Normalize(name)
	if name == "" {
		return
	}
	now := c.now()
	r := Record{Name: name, Source: source, CheckedAt: now, AttemptedAt: now, Addresses: []Address{}, Spare: spare}
	// Follow only the answer chain belonging to the question, regardless of RR order.
	current := name
	ttl := uint32(^uint32(0))
	seen := map[string]bool{}
	terminal := false
	for steps := 0; steps < 16 && !seen[current]; steps++ {
		seen[current] = true
		next := ""
		for _, rr := range m.Answer {
			if cn, ok := rr.(*dns.CNAME); ok && Normalize(cn.Hdr.Name) == current {
				next = Normalize(cn.Target)
				ttl = min(ttl, cn.Hdr.Ttl)
				break
			}
		}
		if next == "" {
			terminal = true
			break
		}
		current = next
	}
	if !terminal {
		c.setError(name, "CNAME chain is cyclic or too long", spare)
		return
	}
	unique := map[string]bool{}
	for _, rr := range m.Answer {
		a, ok := rr.(*dns.A)
		if !ok || Normalize(a.Hdr.Name) != current {
			continue
		}
		life := min(ttl, a.Hdr.Ttl)
		ip := a.A.To4()
		if life == 0 || ip == nil || unique[ip.String()] {
			continue
		}
		unique[ip.String()] = true
		if len(r.Addresses) >= 32 {
			r.Limited = true
			continue
		}
		r.Addresses = append(r.Addresses, Address{IP: ip.String(), ExpiresAt: now.Add(time.Duration(life) * time.Second)})
	}
	slices.SortFunc(r.Addresses, func(a, b Address) int { return strings.Compare(a.IP, b.IP) })
	c.mu.Lock()
	defer c.mu.Unlock()
	if spare && len(r.Addresses) == 0 {
		c.removeLocked(name)
		return
	}
	if source == "observed" {
		r.ObservedAt = now
	} else {
		r.ObservedAt = c.records[name].ObservedAt
	}
	c.put(r)
}

// SetError records a failed attempt while retaining still-valid answers.
func (c *Cache) SetError(name, message string) {
	c.setError(Normalize(name), message, false)
}

// setError retains failure history for a spare name only if it already has a record.
func (c *Cache) setError(name, message string, existingOnly bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, exists := c.records[name]
	if existingOnly && !exists {
		return
	}
	r.Name = name
	r.Error = message
	r.AttemptedAt = c.now()
	if r.Addresses == nil {
		r.Addresses = []Address{}
	}
	c.put(r)
}

// pruneLocked removes expired addresses once the earliest of them has
// expired, and the spare records left without one; the caller holds mu. A
// record that loses an address gets a new slice, as snapshots share the old.
func (c *Cache) pruneLocked() {
	now := c.now()
	if c.expiry.IsZero() || now.Before(c.expiry) {
		return
	}
	var next time.Time
	for name, r := range c.records {
		if slices.ContainsFunc(r.Addresses, func(a Address) bool { return !a.ExpiresAt.After(now) }) {
			c.generation++
			live := make([]Address, 0, len(r.Addresses))
			for _, a := range r.Addresses {
				if a.ExpiresAt.After(now) {
					live = append(live, a)
				}
			}
			if len(live) == 0 && r.Spare {
				delete(c.records, name)
				continue
			}
			r.Addresses = live
			c.records[name] = r
		}
		next = earliestExpiry(next, r.Addresses)
	}
	c.expiry = next
}

// Prune removes expired addresses while retaining name and attempt history.
func (c *Cache) Prune() { c.mu.Lock(); defer c.mu.Unlock(); c.pruneLocked() }

// Generation prunes expired addresses and returns a number that changes
// whenever a name gains or loses an address.
func (c *Cache) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked()
	return c.generation
}

// Addresses returns the unexpired addresses of every name that has one and
// the generation they belong to. The lists share one backing array.
func (c *Cache) Addresses() (map[string][]string, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked()
	names, total := 0, 0
	for _, r := range c.records {
		if len(r.Addresses) > 0 {
			names, total = names+1, total+len(r.Addresses)
		}
	}
	out := make(map[string][]string, names)
	ips := make([]string, 0, total)
	for name, r := range c.records {
		if len(r.Addresses) == 0 {
			continue
		}
		start := len(ips)
		for _, a := range r.Addresses {
			ips = append(ips, a.IP)
		}
		out[name] = ips[start:len(ips):len(ips)]
	}
	return out, c.generation
}

// Snapshot returns the records that keep selects, or all records for a nil
// keep, sorted by name with only their unexpired addresses. keep runs under
// the cache lock and must not use the cache. Records share their address
// slices with the cache.
func (c *Cache) Snapshot(keep func(Record) bool) []Record {
	c.mu.Lock()
	c.pruneLocked()
	var out []Record
	if keep == nil {
		out = make([]Record, 0, len(c.records))
	}
	for _, r := range c.records {
		if keep == nil || keep(r) {
			out = append(out, r)
		}
	}
	c.mu.Unlock()
	slices.SortFunc(out, func(a, b Record) int { return strings.Compare(a.Name, b.Name) })
	if out == nil {
		out = []Record{}
	}
	return out
}
