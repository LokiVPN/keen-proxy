package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// ErrConfigChanged means a conditional Apply lost its configuration revision.
var ErrConfigChanged = errors.New("configuration revision changed")

// ConfigRevision identifies the complete configuration by its deterministic
// JSON. An unavailable revision is empty.
func ConfigRevision(cfg *Config) string {
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
