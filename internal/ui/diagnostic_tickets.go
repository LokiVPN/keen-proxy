package ui

import (
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"slices"
	"sync"
	"time"
)

// diagnosticTickets retains only probe outcomes and pending release targets.
// Tokens are short lived and bound to the verified session when one exists.
type diagnosticTickets struct {
	mu      sync.Mutex
	entries []diagnosticTicket
}

type diagnosticTicket struct {
	token, purpose string
	owner          [sha256.Size]byte
	expires        time.Time
	revision       string
	check          DiagnosticCheckResult
	titles         subscriptionTitles
	target         string
}

func (d *diagnosticTickets) put(ticket diagnosticTicket) string {
	const maxTickets = 16
	now := time.Now()
	ticket.expires, ticket.token = now.Add(5*time.Minute), rand.Text()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = slices.DeleteFunc(d.entries, func(entry diagnosticTicket) bool { return !now.Before(entry.expires) })
	if len(d.entries) == maxTickets {
		d.entries = slices.Delete(d.entries, 0, 1)
	}
	d.entries = append(d.entries, ticket)
	return ticket.token
}

func (d *diagnosticTickets) get(token, purpose string, owner [sha256.Size]byte) (diagnosticTicket, bool) {
	if token == "" {
		return diagnosticTicket{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, entry := range d.entries {
		if entry.token == token && entry.purpose == purpose && entry.owner == owner && time.Now().Before(entry.expires) {
			// A release confirmation is single-use; probe results remain
			// readable after a reload until the ticket expires.
			if entry.target != "" {
				d.entries = slices.Delete(d.entries, i, i+1)
			}
			return entry, true
		}
	}
	return diagnosticTicket{}, false
}

func (p pages) diagnosticsOwner(r *http.Request) [sha256.Size]byte {
	if p.opts.SessionKey != nil {
		return p.opts.SessionKey(r)
	}
	return [sha256.Size]byte{}
}
