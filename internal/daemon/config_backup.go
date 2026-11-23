package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// BackupV1Config keeps raw, a configuration that older releases read, beside
// path as config.v1.yaml, or as config.v1.<unix seconds>.yaml when that name
// is taken. The installer restores config.v1.yaml when it rolls back to such a
// release. The copy has mode 0600, is synced before return and never replaces
// an existing file. It returns the backup path.
func BackupV1Config(path string, raw []byte, now time.Time) (string, error) {
	dir := filepath.Dir(path)
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
		if err := errors.Join(err, f.Close()); err != nil {
			// A partial copy must not occupy the name the installer restores.
			os.Remove(backup)
			return "", err
		}
		return backup, nil
	}
	return "", fmt.Errorf("backups config.v1.yaml and config.v1.%d.yaml already exist in %s", now.Unix(), dir)
}

// keepV1Config backs up the saved file before the first write in the current
// schema replaces a file that older releases can read.
func keepV1Config(path string, previous []byte) error {
	if model.FileSchemaVersion(previous) >= model.SchemaVersion {
		return nil
	}
	if _, err := BackupV1Config(path, previous, time.Now()); err != nil {
		return fmt.Errorf("configuration for older releases was not kept: %w", err)
	}
	return nil
}
