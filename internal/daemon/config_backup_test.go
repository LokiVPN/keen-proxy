package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Older releases read only version 1 files. The first save over such a file
// keeps it byte for byte as config.v1.yaml; later saves leave that copy alone.
func TestApplyBacksUpV1BeforeFirstWrite(t *testing.T) {
	d, path, original := startV1Daemon(t, withConnection(t))
	dir := filepath.Dir(path)
	backup := filepath.Join(dir, "config.v1.yaml")
	if got := d.Config().SchemaVersion; got != 1 {
		t.Fatalf("loaded schema_version %d, want 1 until the first save", got)
	}
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("startup wrote a backup: %v", err)
	}
	if err := d.Apply(context.Background(), d.Config()); err != nil {
		t.Fatal(err)
	}
	assertSavedBytes(t, backup, original)
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode: %v, %v", info, err)
	}
	saved, err := model.Load(path)
	if err != nil || saved.SchemaVersion != 2 {
		t.Fatalf("saved config = %+v, %v; want schema_version 2", saved, err)
	}
	if got := d.Config().SchemaVersion; got != 2 {
		t.Fatalf("applied schema_version %d, want 2", got)
	}

	if err := d.Apply(context.Background(), d.Config()); err != nil {
		t.Fatal(err)
	}
	assertSavedBytes(t, backup, original)
	if matches, err := filepath.Glob(filepath.Join(dir, "config.v1*")); err != nil || len(matches) != 1 {
		t.Fatalf("backups after a second save = %v, %v", matches, err)
	}
}

// Installer starter files hold only schema_version, lan and, from older
// OpenWrt installers, api. A rollback needs nothing from them, so no backup is
// kept. The daemon runs on test settings in memory, as main passes them.
func TestApplySkipsBackupOfPlaceholderV1(t *testing.T) {
	for _, placeholder := range []string{
		"schema_version: 1\n",
		"schema_version: 1\nlan:\n  interface: br-lan\n",
		"schema_version: 1\napi:\n  token_file: /etc/keenproxy/token\nlan:\n  interface: br-lan\n",
	} {
		t.Run(fmt.Sprintf("%d bytes", len(placeholder)), func(t *testing.T) {
			d, path := startDaemonOn(t, []byte(placeholder), quietConfig(t))
			if err := d.Apply(context.Background(), d.Config()); err != nil {
				t.Fatal(err)
			}
			if matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "config.v1*")); err != nil || len(matches) != 0 {
				t.Fatalf("placeholder backups = %v, %v", matches, err)
			}
			if saved, err := model.Load(path); err != nil || saved.SchemaVersion != 2 {
				t.Fatalf("saved config = %+v, %v; want schema_version 2", saved, err)
			}
		})
	}
}

// A version 1 file with settings beyond the starter keys is kept even
// without connections or subscriptions.
func TestApplyBacksUpV1WithoutProfiles(t *testing.T) {
	d, path, original := startV1Daemon(t, quietConfig(t))
	if err := d.Apply(context.Background(), d.Config()); err != nil {
		t.Fatal(err)
	}
	assertSavedBytes(t, filepath.Join(filepath.Dir(path), "config.v1.yaml"), original)
}

// Without a backup, a save must not replace a file that older releases read.
func TestApplyKeepsV1FileWhenBackupFails(t *testing.T) {
	d, path, original := startV1Daemon(t, withConnection(t))
	dir := filepath.Dir(path)
	// Directories take config.v1.yaml and each timestamped name for two minutes.
	names := []string{"config.v1.yaml"}
	for now, s := time.Now().Unix(), int64(-1); s <= 120; s++ {
		names = append(names, fmt.Sprintf("config.v1.%d.yaml", now+s))
	}
	for _, name := range names {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	err := d.Apply(context.Background(), d.Config())
	if err == nil || !strings.Contains(err.Error(), "not saved") || !strings.Contains(err.Error(), "older releases") {
		t.Fatalf("apply without a free backup name: %v", err)
	}
	assertSavedBytes(t, path, original)
	if _, err := os.Stat(path + ".previous"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused save wrote the previous configuration: %v", err)
	}
}

func TestBackupV1ConfigNeverReplacesAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	first := filepath.Join(dir, "config.v1.yaml")
	if err := os.WriteFile(first, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	got, err := backupV1Config(path, []byte("second\n"), now, slog.New(slog.DiscardHandler))
	if want := filepath.Join(dir, "config.v1.1700000000.yaml"); err != nil || got != want {
		t.Fatalf("backup = %q, %v; want %q", got, err, want)
	}
	if _, err := backupV1Config(path, []byte("third\n"), now, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("a third backup in the same second replaced an existing file")
	}
	assertSavedBytes(t, first, []byte("first\n"))
	assertSavedBytes(t, got, []byte("second\n"))
}

// startV1Daemon saves cfg as a version 1 file, led by a comment that a
// re-marshal would drop, and runs a daemon from it. It returns the file bytes.
func startV1Daemon(t *testing.T, cfg *model.Config) (*Daemon, string, []byte) {
	t.Helper()
	cfg.SchemaVersion = 1
	raw, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte("# saved by an older release\n"), raw...)
	d, path := startDaemonOn(t, original, nil)
	return d, path, original
}

// startDaemonOn saves raw as the configuration file and runs a daemon on it,
// or on cfg when set, as main passes the configuration it loaded or reset.
func startDaemonOn(t *testing.T, raw []byte, cfg *model.Config) (*Daemon, string) {
	t.Helper()
	holdMemoryLimit(t)
	baseline := int64(300) * memoryMiB
	debug.SetMemoryLimit(baseline)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	d := newMemoryDaemon(t, path, &gateRunner{})
	d.opt.Config = cfg
	runDaemon(t, d, baseline)
	return d, path
}

// withConnection returns a quiet configuration with one connection profile,
// which makes its file worth keeping for older releases.
func withConnection(t *testing.T) *model.Config {
	cfg := quietConfig(t)
	cfg.Connections = []model.Connection{{ID: "vpn", Name: "VPN", Type: model.ConnLink, Link: "socks5://203.0.113.1:1080"}}
	return cfg
}

func assertSavedBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
	}
}

// A read error other than not-found hides what the first save would replace,
// so the save is refused and the file stays.
func TestFirstSaveFailsClosedOnUnreadableConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	d, path, original := startV1Daemon(t, withConnection(t))
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })
	if err := d.Apply(context.Background(), d.Config()); err == nil || !strings.Contains(err.Error(), "not saved") {
		t.Fatalf("apply over an unreadable file: %v", err)
	}
	os.Chmod(path, 0o600)
	assertSavedBytes(t, path, original)
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "config.v1*")); len(matches) != 0 {
		t.Fatalf("backups = %v", matches)
	}
}

func failDirSync(t *testing.T, err error) {
	t.Helper()
	old := fsyncDir
	fsyncDir = func(*os.File) error { return err }
	t.Cleanup(func() { fsyncDir = old })
}

// Filesystems that cannot fsync a directory are tolerated, and a directory
// sync failure after the config was replaced is a durability warning: the
// file is saved and the Apply stands.
func TestDirectorySyncUnsupportedIsAWarning(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"EINVAL", syscall.EINVAL}, {"ENOTSUP", syscall.ENOTSUP}, {"EIO after the rename", syscall.EIO}} {
		t.Run(tc.name, func(t *testing.T) {
			d, path, original := startV1Daemon(t, quietConfig(t))
			failDirSync(t, tc.err)
			// A backup is kept first; only unsupported syncs let that proceed.
			err := d.Apply(context.Background(), d.Config())
			if tc.err == syscall.EIO {
				if err == nil {
					t.Fatal("first save went on after the backup directory sync failed")
				}
				assertSavedBytes(t, path, original)
				// With the backup in place, the replace itself only warns.
				failDirSync(t, nil)
				if err := d.Apply(context.Background(), d.Config()); err != nil {
					t.Fatal(err)
				}
				failDirSync(t, tc.err)
				if err := d.Apply(context.Background(), d.Config()); err != nil {
					t.Fatalf("durability warning failed the save: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unsupported directory sync failed the save: %v", err)
			}
			if saved, err := model.Load(path); err != nil || saved.SchemaVersion != 2 {
				t.Fatalf("saved config = %+v, %v; want schema_version 2", saved, err)
			}
			if !d.configCurrent {
				t.Fatal("daemon did not record the file as current")
			}
		})
	}
}

// A directory sync failure after the config was replaced still saves it.
func TestDirectorySyncFailureAfterRenameKeepsTheSave(t *testing.T) {
	d, path := startDaemonOn(t, []byte("schema_version: 2\n"), quietConfig(t))
	failDirSync(t, syscall.EIO)
	cfg := d.Config()
	cfg.LAN.Interface = "br9"
	if err := d.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if saved, err := model.Load(path); err != nil || saved.LAN.Interface != "br9" {
		t.Fatalf("saved config = %+v, %v", saved, err)
	}
}

// savedDaemon is a daemon, not running, on a saved schema 2 file whose
// warnings go to logs.
func savedDaemon(t *testing.T, logs *bytes.Buffer) (*Daemon, *model.Config, string) {
	t.Helper()
	cfg := quietConfig(t)
	path := writeSavedConfig(t, cfg)
	d := newMemoryDaemon(t, path, &gateRunner{})
	d.log = slog.New(slog.NewTextHandler(logs, nil))
	return d, cfg, path
}

// The warning for a filesystem that cannot sync a directory goes to the
// daemon's log, which feeds the system journal, not to the process default.
func TestUnsupportedDirectorySyncWarnsInTheDaemonLog(t *testing.T) {
	var logs, fallback bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&fallback, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	d, cfg, _ := savedDaemon(t, &logs)
	failDirSync(t, syscall.EINVAL)
	cfg.LAN.Interface = "br9"
	if err := d.persistConfig(cfg, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "directory sync is not supported") {
		t.Errorf("daemon log = %q", logs.String())
	}
	if strings.Contains(fallback.String(), "directory sync") {
		t.Errorf("default logger got the warning: %q", fallback.String())
	}
}

// Failed first saves repeat the backup step; identical bytes are kept once.
func TestRepeatedFailedFirstSaveDoesNotPileUpBackups(t *testing.T) {
	d, path, original := startV1Daemon(t, withConnection(t))
	// A directory in place of the rollback copy fails the save after the backup.
	if err := os.Mkdir(path+".previous", 0o700); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := d.Apply(context.Background(), d.Config()); err == nil {
			t.Fatal("apply succeeded without a rollback copy")
		}
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "config.v1*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("backups after repeated failures = %v, %v", matches, err)
	}
	assertSavedBytes(t, matches[0], original)
}
