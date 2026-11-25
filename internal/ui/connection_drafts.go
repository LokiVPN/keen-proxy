package ui

import (
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/connectionimport"
)

const (
	connectionDraftLifetime = 5 * time.Minute
	connectionSessionCookie = "keenproxy_connection_session"
)

// connectionDrafts owns the private payloads. A browser can carry only an
// opaque token for a particular session, configuration and step.
type connectionDrafts struct {
	mu      sync.Mutex
	entries []connectionDraft
}

type connectionDraft struct {
	token, rev string
	session    [sha256.Size]byte
	expires    time.Time
	location   wizardLocation
	candidates []connectionimport.Draft
}

func (d *connectionDrafts) put(draft connectionDraft, now time.Time) string {
	const limit = 4
	draft.token = rand.Text()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(now)
	if !now.Before(draft.expires) {
		return ""
	}
	if len(d.entries) == limit {
		d.entries = slices.Delete(d.entries, 0, 1)
	}
	d.entries = append(d.entries, draft)
	return draft.token
}

func (d *connectionDrafts) take(token, rev string, session [sha256.Size]byte, choosing bool, now time.Time) (connectionDraft, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(now)
	for i, draft := range d.entries {
		if draft.token == token && draft.rev == rev && draft.session == session && (len(draft.candidates) > 1) == choosing {
			d.entries = slices.Delete(d.entries, i, i+1)
			return draft, true
		}
	}
	return connectionDraft{}, false
}

func (d *connectionDrafts) expire(now time.Time) {
	d.entries = slices.DeleteFunc(d.entries, func(draft connectionDraft) bool {
		return !now.Before(draft.expires)
	})
}

// wizardSession prefers the verified KeeneticOS session. Trusted loopback
// browsers lack one, so an HTTP-only nonce separates their drafts.
func (p pages) wizardSession(w http.ResponseWriter, r *http.Request, create bool) [sha256.Size]byte {
	if p.opts.SessionKey != nil {
		if key := p.opts.SessionKey(r); key != ([sha256.Size]byte{}) {
			return key
		}
	}
	cookie, err := r.Cookie(connectionSessionCookie)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 128 {
		if !create {
			return [sha256.Size]byte{}
		}
		cookie = &http.Cookie{
			Name: connectionSessionCookie, Value: rand.Text(), Path: "/connections",
			HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
		}
		http.SetCookie(w, cookie)
	}
	return sha256.Sum256([]byte("loopback\x00" + p.opts.requestUser(r) + "\x00" + cookie.Value))
}
