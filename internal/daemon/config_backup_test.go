package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// Older releases read only version 1 files. The first save over such a file
// keeps it byte for byte as config.v1.yaml; later saves leave that copy alone.
func TestApplyBacksUpV1BeforeFirstWrite(t *testing.T) {
	holdMemoryLimit(t)
	baseline := int64(300) * memoryMiB
	debug.SetMemoryLimit(baseline)
	cfg := quietConfig(t)
	cfg.SchemaVersion = 1
	raw, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte("# saved by an older release\n"), raw...)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "config.v1.yaml")

	d, _ := startMemoryDaemon(t, path, &gateRunner{}, baseline)
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

func TestBackupV1ConfigNeverReplacesAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	first := filepath.Join(dir, "config.v1.yaml")
	if err := os.WriteFile(first, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	got, err := BackupV1Config(path, []byte("second\n"), now)
	if want := filepath.Join(dir, "config.v1.1700000000.yaml"); err != nil || got != want {
		t.Fatalf("backup = %q, %v; want %q", got, err, want)
	}
	if _, err := BackupV1Config(path, []byte("third\n"), now); err == nil {
		t.Fatal("a third backup in the same second replaced an existing file")
	}
	assertSavedBytes(t, first, []byte("first\n"))
	assertSavedBytes(t, got, []byte("second\n"))
}

func assertSavedBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
	}
}
