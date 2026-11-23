package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// resetReason replaces the load error in reset messages: that error can quote
// a share link together with its credentials.
const resetReason = "an older or unreadable configuration does not load in this release"

// loadOrReset loads the configuration file. A file older releases wrote
// (schema_version below 2) or whose version cannot be read, and that this
// release cannot load, such as a v0.10 file with removed sections, is
// replaced by defaults that keep only the API address, the LAN section and
// the first valid subscription, so an unattended upgrade keeps the VPN
// subscription. A schema 2 file that does not load returns the load error.
//
// With write, the original bytes are first kept as config.v1.yaml (see
// daemon.BackupV1Config) and the reset file is then saved in the current
// schema. Without write nothing is changed and the reset is only reported.
// A file that cannot be read returns the read error, as model.Load does.
// Reset messages never contain the load error or the subscription URL.
func loadOrReset(path string, log *slog.Logger, write bool) (*model.Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := model.Parse(raw)
	if err == nil || model.FileSchemaVersion(raw) >= model.SchemaVersion {
		return cfg, err
	}
	cfg = resetConfig(raw)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration reset: defaults are invalid: %w", err)
	}
	kept := ""
	if len(cfg.Subscriptions) > 0 {
		kept = cfg.Subscriptions[0].ID
	}
	if !write {
		log.Warn("configuration would be reset after upgrade", "reason", resetReason, "subscription_kept", kept)
		return cfg, nil
	}
	data, err := cfg.Marshal()
	if err != nil {
		return nil, err
	}
	backup, err := daemon.BackupV1Config(path, raw, time.Now())
	if err != nil {
		return nil, fmt.Errorf("configuration reset: original configuration was not kept: %w", err)
	}
	if err := replaceFile(path, data); err != nil {
		return nil, fmt.Errorf("configuration reset: reset configuration was not saved: %w", err)
	}
	log.Warn("configuration reset after upgrade", "reason", resetReason, "backup", backup, "subscription_kept", kept)
	return cfg, nil
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

// replaceFile atomically replaces path with a synced private file.
func replaceFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
