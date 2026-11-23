package main

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// v010Config was written by v0.10. Its filters section, the preset metadata
// in groups and unknown keys inside lan and subscriptions no longer load.
const v010Config = `schema_version: 1
api:
  listen: 192.0.2.1:8086
  token_file: /opt/etc/keenproxy/token
lan:
  interface: br1
  wan: eth3
  trusted: [192.0.2.0/24]
filters:
  - id: ads
    url: https://filters.example.net/ads.txt
subscriptions:
  - id: Not Valid
    url: https://sub.example.net/s/bad
  - id: lokivpn
    url: https://sub.example.net/s/x
    name: LokiVPN
groups:
  - name: Video
    target: direct
    entries: [video.example]
    preset: {id: video}
`

func TestLoadOrResetKeepsLoadableV1Config(t *testing.T) {
	const body = `schema_version: 1
api:
  listen: 127.0.0.1:8086
  token_file: /opt/etc/keenproxy/token
groups:
  - name: Video
    target: direct
    entries: [video.example]
  - name: Work
    target: block
    entries: [work.example]
`
	dir, path := writeConfigFile(t, body)
	log, logs := bufferLog()
	cfg, err := loadOrReset(path, log, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != 1 || len(cfg.Groups) != 2 || cfg.Groups[0].Name != "Video" || cfg.Groups[1].Name != "Work" {
		t.Fatalf("loaded config changed: %+v", cfg)
	}
	assertFileBytes(t, path, body)
	assertDirNames(t, dir, "config.yaml")
	if logs.Len() != 0 {
		t.Fatalf("loadable config logged: %s", logs)
	}
}

func TestLoadOrResetCarriesSubscription(t *testing.T) {
	dir, path := writeConfigFile(t, v010Config)
	log, logs := bufferLog()
	cfg, err := loadOrReset(path, log, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []subscription.Source{{ID: "lokivpn", URL: "https://sub.example.net/s/x"}}
	if cfg.SchemaVersion != 2 || !slices.Equal(cfg.Subscriptions, want) || cfg.API.Listen != "192.0.2.1:8086" ||
		cfg.LAN != (model.LAN{Interface: "br1", WAN: "eth3"}) || len(cfg.Groups) != 0 {
		t.Fatalf("reset config = %+v", cfg)
	}
	backup := filepath.Join(dir, "config.v1.yaml")
	assertFileBytes(t, backup, v010Config)
	assertPrivate(t, backup)
	assertPrivate(t, path)
	raw, err := os.ReadFile(path)
	if err != nil || model.FileSchemaVersion(raw) != 2 {
		t.Fatalf("saved file %q, %v; want schema_version 2", raw, err)
	}
	saved, err := model.Load(path)
	if err != nil || !bytes.Equal(mustMarshal(t, saved), mustMarshal(t, cfg)) {
		t.Fatalf("saved file differs from the returned config: %v", err)
	}
	out := logs.String()
	if strings.Count(out, "configuration reset after upgrade") != 1 || !strings.Contains(out, backup) || !strings.Contains(out, "lokivpn") {
		t.Fatalf("reset log = %s", out)
	}
	if strings.Contains(out, "example.net") {
		t.Fatalf("reset log disclosed a URL: %s", out)
	}

	// The next start loads the reset file as is and keeps the only backup.
	logs.Reset()
	again, err := loadOrReset(path, log, true)
	if err != nil || !slices.Equal(again.Subscriptions, want) {
		t.Fatalf("second start = %+v, %v", again, err)
	}
	assertFileBytes(t, backup, v010Config)
	assertDirNames(t, dir, "config.v1.yaml", "config.yaml")
	if logs.Len() != 0 {
		t.Fatalf("second start logged: %s", logs)
	}
}

func TestLoadOrResetNeverOverwritesBackup(t *testing.T) {
	dir, path := writeConfigFile(t, v010Config)
	const earlier = "schema_version: 1\n# kept by an earlier upgrade\n"
	backup := filepath.Join(dir, "config.v1.yaml")
	if err := os.WriteFile(backup, []byte(earlier), 0o600); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Unix()
	if _, err := loadOrReset(path, slog.New(slog.NewTextHandler(io.Discard, nil)), true); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Unix()
	assertFileBytes(t, backup, earlier)
	matches, err := filepath.Glob(filepath.Join(dir, "config.v1.*.yaml"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("timestamped backups = %v, %v", matches, err)
	}
	name := regexp.MustCompile(`^config\.v1\.(\d+)\.yaml$`).FindStringSubmatch(filepath.Base(matches[0]))
	if name == nil {
		t.Fatalf("backup name %s", matches[0])
	}
	if seconds, _ := strconv.ParseInt(name[1], 10, 64); seconds < before || seconds > after {
		t.Fatalf("backup timestamp %d outside [%d, %d]", seconds, before, after)
	}
	assertFileBytes(t, matches[0], v010Config)
	assertPrivate(t, matches[0])
}

func TestLoadOrResetInvalidYAML(t *testing.T) {
	const garbage = "\x00\xff{{ not: [yaml\n"
	dir, path := writeConfigFile(t, garbage)
	log, logs := bufferLog()
	cfg, err := loadOrReset(path, log, true)
	if err != nil {
		t.Fatal(err)
	}
	defaults := &model.Config{}
	defaults.Defaults()
	if !bytes.Equal(mustMarshal(t, cfg), mustMarshal(t, defaults)) {
		t.Fatalf("reset config = %+v, want defaults", cfg)
	}
	assertFileBytes(t, filepath.Join(dir, "config.v1.yaml"), garbage)
	saved, err := model.Load(path)
	if err != nil || !bytes.Equal(mustMarshal(t, saved), mustMarshal(t, defaults)) {
		t.Fatalf("saved config = %+v, %v; want defaults", saved, err)
	}
	if strings.Count(logs.String(), "configuration reset after upgrade") != 1 {
		t.Fatalf("reset log = %s", logs)
	}
}

func TestLoadOrResetMissingFileFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrReset(filepath.Join(dir, "config.yaml"), slog.New(slog.NewTextHandler(io.Discard, nil)), true); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	assertDirNames(t, dir)
}

// The installer dry-runs a candidate binary against the current file; that
// check must accept a v0.10 file and must not change anything.
func TestDryRunAcceptsV010ConfigWithoutWriting(t *testing.T) {
	dir, path := writeConfigFile(t, v010Config)
	work := t.TempDir()
	stdout, stderr, code := runKeenproxy(t, "-dry-run", "-config", path,
		"-arp", filepath.Join(work, "arp"), "-rule-sets", filepath.Join(work, "rule-sets"))
	if code != 0 || !strings.Contains(stdout, "# sing-box") {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
	var notices []string
	for line := range strings.SplitSeq(stdout+stderr, "\n") {
		if strings.Contains(line, "configuration would be reset after upgrade") {
			notices = append(notices, line)
		}
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "lokivpn") || strings.Contains(notices[0], "example.net") {
		t.Fatalf("reset notices = %q", notices)
	}
	assertFileBytes(t, path, v010Config)
	assertDirNames(t, dir, "config.yaml")
	assertDirNames(t, work)
}

func writeConfigFile(t *testing.T, body string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func bufferLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

func mustMarshal(t *testing.T, cfg *model.Config) []byte {
	t.Helper()
	raw, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertFileBytes(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
	}
}

func assertPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode: %v, %v; want 0600", path, info, err)
	}
}

func assertDirNames(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s holds %q, want %q", dir, got, want)
	}
}
