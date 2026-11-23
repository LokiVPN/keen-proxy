package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// backupV1Config keeps raw, a configuration that older releases read, beside
// path as config.v1.yaml, or as config.v1.<unix seconds>.yaml when that name
// is taken. The installer restores config.v1.yaml when it rolls back to such a
// release. The copy has mode 0600, never replaces an existing file, and it and
// its directory entry are synced before return, so a crash after the original
// is replaced cannot lose both. It returns the backup path.
func backupV1Config(path string, raw []byte, now time.Time, log *slog.Logger) (string, error) {
	dir := filepath.Dir(path)
	if existing := newestIdenticalBackup(dir, raw); existing != "" {
		return existing, nil
	}
	for _, name := range []string{"config.v1.yaml", fmt.Sprintf("config.v1.%d.yaml", now.Unix())} {
		backup := filepath.Join(dir, name)
		f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
		if err == nil {
			err = syncDir(dir, log)
		}
		if err != nil {
			// A copy that is partial or may not survive a crash must not
			// occupy the name the installer restores.
			os.Remove(backup)
			return "", err
		}
		return backup, nil
	}
	return "", fmt.Errorf("backups config.v1.yaml and config.v1.%d.yaml already exist in %s", now.Unix(), dir)
}

// keepV1Config backs up the saved file before the first write in the current
// schema replaces a file that older releases can read, including a v0.10 or
// unreadable file the daemon started from after a reset in memory. An
// installer starter file (see model.FileIsPlaceholder) has nothing a rollback
// needs and is not kept. It returns the backup path, or "" when nothing was
// kept.
func keepV1Config(path string, previous []byte, log *slog.Logger) (string, error) {
	if model.FileSchemaVersion(previous) >= model.SchemaVersion || model.FileIsPlaceholder(previous) {
		return "", nil
	}
	backup, err := backupV1Config(path, previous, time.Now(), log)
	if err != nil {
		return "", fmt.Errorf("configuration for older releases was not kept: %w", err)
	}
	return backup, nil
}

// newestIdenticalBackup returns the most recently written config.v1*.yaml in
// dir when it holds exactly raw, so repeated failed first saves keep one copy.
func newestIdenticalBackup(dir string, raw []byte) string {
	matches, _ := filepath.Glob(filepath.Join(dir, "config.v1*.yaml"))
	var newest string
	var newestTime time.Time
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if newest == "" || info.ModTime().After(newestTime) {
			newest, newestTime = m, info.ModTime()
		}
	}
	if newest == "" {
		return ""
	}
	if got, err := os.ReadFile(newest); err != nil || !bytes.Equal(got, raw) {
		return ""
	}
	return newest
}
