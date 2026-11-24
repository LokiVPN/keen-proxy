package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Revision identifies the complete applied configuration by the SHA-256 of
// its compact, deterministic JSON. An unavailable revision is empty.
func Revision(cfg *model.Config) string {
	if cfg == nil {
		return ""
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// checkRevision returns the applied snapshot to edit once the submitted
// revision matches. Multipart handlers parse their bounded body first.
// A write handler must keep this check and its apply ordered with respect
// to other writers.
func (p pages) checkRevision(r *http.Request) (*model.Config, string) {
	if err := r.ParseForm(); err == nil {
		if revs := r.PostForm["rev"]; len(revs) == 1 && revs[0] != "" {
			cfg := p.deps.Config()
			if revs[0] == Revision(cfg) {
				return cfg, ""
			}
		}
	}
	return nil, localized(r)["revision_changed"]
}
