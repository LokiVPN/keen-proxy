package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// resetReason replaces the load error in reset messages: that error can quote
// a share link together with its credentials.
const resetReason = "an older or unreadable configuration does not load in this release"

// loadOrReset loads the configuration file. A file older releases wrote
// (schema_version below 2) or whose version cannot be read, and that this
// release cannot load, such as a v0.10 file with removed sections, is reset to
// defaults that keep only the API address, the LAN section and the first valid
// subscription, so an unattended upgrade keeps the VPN subscription; reset
// reports that case. A schema 2 file that does not load returns the load
// error, and a file that cannot be read returns the read error, as model.Load
// does.
//
// The reset happens in memory: loadOrReset never changes a file. The daemon
// replaces the file at its first save, after keeping the original bytes as
// config.v1.yaml (see daemon.Options.Config). Until then an older release
// still reads the file, and every start computes the same reset from it.
func loadOrReset(path string) (cfg *model.Config, reset bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	cfg, err = model.Parse(raw)
	if err == nil || model.FileSchemaVersion(raw) >= model.SchemaVersion {
		return cfg, false, err
	}
	cfg = resetConfig(raw)
	if err := cfg.Validate(); err != nil {
		return nil, false, fmt.Errorf("configuration reset: defaults are invalid: %w", err)
	}
	return cfg, true, nil
}

// startupConfig returns the configuration the daemon starts with and reports a
// reset once. Like loadOrReset it changes no file.
func startupConfig(path string, log *slog.Logger) (*model.Config, error) {
	cfg, reset, err := loadOrReset(path)
	if err == nil && reset {
		logReset(log, "configuration reset after upgrade; the first save keeps the file for older releases", cfg)
	}
	return cfg, err
}

// logReset reports a reset without the load error or the subscription URL.
func logReset(log *slog.Logger, msg string, cfg *model.Config) {
	kept := ""
	if len(cfg.Subscriptions) > 0 {
		kept = cfg.Subscriptions[0].ID
	}
	log.Warn(msg, "reason", resetReason, "subscription_kept", kept)
}

// resetConfig returns defaults with the settings a reset keeps. Decoding is
// lenient: unknown fields are dropped and unreadable values are not kept.
func resetConfig(raw []byte) *model.Config {
	var old struct {
		API struct {
			Listen string `yaml:"listen"`
		} `yaml:"api"`
		LAN           model.LAN             `yaml:"lan"`
		Subscriptions []subscription.Source `yaml:"subscriptions"`
	}
	// Decoding continues past type errors; affected values stay empty.
	_ = yaml.Unmarshal(raw, &old)
	cfg := &model.Config{LAN: old.LAN}
	if _, err := netip.ParseAddrPort(old.API.Listen); err == nil {
		cfg.API.Listen = old.API.Listen
	}
	for _, source := range old.Subscriptions {
		if subscription.ValidateSource(source) == nil {
			cfg.Subscriptions = []subscription.Source{source}
			break
		}
	}
	cfg.Defaults()
	return cfg
}
