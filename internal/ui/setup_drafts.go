package ui

import (
	"crypto/rand"
	"slices"
	"sync"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

const setupDraftLifetime = 5 * time.Minute

// setupDrafts keeps checked URLs server-side. Only an expiring, single-use
// token tied to the managing user, revision and action travels in the form.
type setupDrafts struct {
	mu      sync.Mutex
	entries []setupDraft
}

type setupDraft struct {
	token, user, rev, path string
	expires                time.Time
	preview                subscription.PreviewRef
}

func (d *setupDrafts) save(draft setupDraft, now time.Time) string {
	const maxDrafts = 4
	draft.token = rand.Text()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(now)
	if len(d.entries) == maxDrafts {
		d.entries = slices.Delete(d.entries, 0, 1)
	}
	d.entries = append(d.entries, draft)
	return draft.token
}

func (d *setupDrafts) take(token, rev, user, path string, now time.Time) subscription.PreviewRef {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(now)
	for i, draft := range d.entries {
		if draft.token == token && draft.rev == rev && draft.user == user && draft.path == path {
			d.entries = slices.Delete(d.entries, i, i+1)
			return draft.preview
		}
	}
	return subscription.PreviewRef{}
}

func (d *setupDrafts) expire(now time.Time) {
	d.entries = slices.DeleteFunc(d.entries, func(draft setupDraft) bool {
		return !now.Before(draft.expires)
	})
}
