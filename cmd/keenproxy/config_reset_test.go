package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/daemon"
	"github.com/ordo-systems/keen-proxy/internal/devices"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
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
	cfg, err := startupConfig(path, log)
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

// The reset happens in memory: startup, a restart and a dry run leave the
// v0.10 file alone, so an older release can still read it. The first save
// keeps it byte for byte as config.v1.yaml and writes schema 2.
func TestLoadOrResetCarriesSubscription(t *testing.T) {
	dir, path := writeConfigFile(t, v010Config)
	log, logs := bufferLog()
	cfg, err := startupConfig(path, log)
	if err != nil {
		t.Fatal(err)
	}
	want := []subscription.Source{{ID: "lokivpn", URL: "https://sub.example.net/s/x"}}
	if cfg.SchemaVersion != 2 || !slices.Equal(cfg.Subscriptions, want) || cfg.API.Listen != "192.0.2.1:8086" ||
		cfg.LAN != (model.LAN{Interface: "br1", WAN: "eth3"}) || len(cfg.Groups) != 0 {
		t.Fatalf("reset config = %+v", cfg)
	}
	out := logs.String()
	if strings.Count(out, "configuration reset after upgrade") != 1 || !strings.Contains(out, "lokivpn") {
		t.Fatalf("reset log = %s", out)
	}
	if strings.Contains(out, "example.net") {
		t.Fatalf("reset log disclosed a URL: %s", out)
	}
	first := mustMarshal(t, cfg)

	d := startDaemon(t, path, cfg)
	assertFileBytes(t, path, v010Config)
	assertDirNames(t, dir, "config.yaml")
	again, reset, err := loadOrReset(path)
	if err != nil || !reset || !bytes.Equal(mustMarshal(t, again), first) {
		t.Fatalf("restart before a save = %+v, reset %t, %v; want the same reset", again, reset, err)
	}

	if err := d.Apply(context.Background(), d.Config()); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "config.v1.yaml")
	assertFileBytes(t, backup, v010Config)
	assertPrivate(t, backup)
	assertPrivate(t, path)
	raw, err := os.ReadFile(path)
	if err != nil || model.FileSchemaVersion(raw) != 2 {
		t.Fatalf("saved file %q, %v; want schema_version 2", raw, err)
	}
	saved, reset, err := loadOrReset(path)
	if err != nil || reset || !slices.Equal(saved.Subscriptions, want) || saved.API.Listen != "192.0.2.1:8086" ||
		saved.LAN != (model.LAN{Interface: "br1", WAN: "eth3"}) {
		t.Fatalf("saved config = %+v, reset %t, %v", saved, reset, err)
	}
	if !bytes.Equal(mustMarshal(t, saved), mustMarshal(t, d.Config())) {
		t.Fatal("saved file differs from the applied configuration")
	}
	if err := d.Apply(context.Background(), d.Config()); err != nil {
		t.Fatal(err)
	}
	assertFileBytes(t, backup, v010Config)
	// One backup, the rollback copy of the previous save and no staged files.
	assertDirNames(t, dir, "config.v1.yaml", "config.yaml", "config.yaml.previous")
	assertPrivate(t, path+".previous")
}

// A backup an earlier upgrade left behind is never replaced: the first save
// after a reset keeps the file under a timestamped name instead.
func TestFirstSaveAfterResetNeverOverwritesBackup(t *testing.T) {
	dir, path := writeConfigFile(t, v010Config)
	const earlier = "schema_version: 1\n# kept by an earlier upgrade\n"
	backup := filepath.Join(dir, "config.v1.yaml")
	if err := os.WriteFile(backup, []byte(earlier), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, reset, err := loadOrReset(path)
	if err != nil || !reset {
		t.Fatalf("reset = %t, %v", reset, err)
	}
	d := startDaemon(t, path, cfg)
	assertDirNames(t, dir, "config.v1.yaml", "config.yaml")
	before := time.Now().Unix()
	if err := d.Apply(context.Background(), d.Config()); err != nil {
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

// An unreadable file starts the daemon with defaults in memory and stays as it
// is until the first save, which keeps it as config.v1.yaml.
func TestLoadOrResetInvalidYAML(t *testing.T) {
	const garbage = "\x00\xff{{ not: [yaml\n"
	dir, path := writeConfigFile(t, garbage)
	log, logs := bufferLog()
	cfg, err := startupConfig(path, log)
	if err != nil {
		t.Fatal(err)
	}
	defaults := &model.Config{}
	defaults.Defaults()
	if !bytes.Equal(mustMarshal(t, cfg), mustMarshal(t, defaults)) {
		t.Fatalf("reset config = %+v, want defaults", cfg)
	}
	if strings.Count(logs.String(), "configuration reset after upgrade") != 1 {
		t.Fatalf("reset log = %s", logs)
	}
	d := startDaemon(t, path, cfg)
	assertFileBytes(t, path, garbage)
	assertDirNames(t, dir, "config.yaml")

	if err := d.Apply(context.Background(), d.Config()); err != nil {
		t.Fatal(err)
	}
	assertFileBytes(t, filepath.Join(dir, "config.v1.yaml"), garbage)
	saved, reset, err := loadOrReset(path)
	if err != nil || reset || saved.SchemaVersion != 2 || !bytes.Equal(mustMarshal(t, saved), mustMarshal(t, d.Config())) {
		t.Fatalf("saved config = %+v, reset %t, %v", saved, reset, err)
	}
}

// A schema 2 file was written by this release or a newer one. A file of that
// kind that does not load stays an error instead of being reset.
func TestLoadOrResetKeepsBrokenV2AsError(t *testing.T) {
	const body = "schema_version: 2\nfilters: []\n"
	dir, path := writeConfigFile(t, body)
	log, logs := bufferLog()
	if _, err := startupConfig(path, log); err == nil || !strings.Contains(err.Error(), "filters") {
		t.Fatalf("broken schema 2 file: %v", err)
	}
	assertFileBytes(t, path, body)
	assertDirNames(t, dir, "config.yaml")
	if logs.Len() != 0 {
		t.Fatalf("broken schema 2 file logged: %s", logs)
	}
	work := t.TempDir()
	if stdout, stderr, code := runKeenproxy(t, "-dry-run", "-config", path,
		"-arp", filepath.Join(work, "arp"), "-rule-sets", filepath.Join(work, "rule-sets")); code == 0 {
		t.Fatalf("dry run accepted a broken schema 2 file: stdout %q stderr %q", stdout, stderr)
	}
	assertFileBytes(t, path, body)
	assertDirNames(t, dir, "config.yaml")
}

// v1BrokenLink fails strict loading with an error that quotes the share link,
// including its credentials.
const v1BrokenLink = `schema_version: 1
connections:
  - id: broken
    name: Broken
    type: link
    link: vless://fixture-secret@[bad
subscriptions:
  - id: lokivpn
    url: https://sub.example.net/s/x
`

func TestResetMessagesOmitTheLoadError(t *testing.T) {
	if _, err := model.Parse([]byte(v1BrokenLink)); err == nil || !strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("fixture no longer produces an error that quotes the link: %v", err)
	}
	dir, path := writeConfigFile(t, v1BrokenLink)
	work := t.TempDir()
	stdout, stderr, code := runKeenproxy(t, "-dry-run", "-config", path,
		"-arp", filepath.Join(work, "arp"), "-rule-sets", filepath.Join(work, "rule-sets"))
	if code != 0 || !strings.Contains(stderr, "configuration would be reset after upgrade") {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
	log, logs := bufferLog()
	cfg, err := startupConfig(path, log)
	if err != nil || len(cfg.Subscriptions) != 1 || len(cfg.Connections) != 0 {
		t.Fatalf("reset = %+v, %v", cfg, err)
	}
	assertFileBytes(t, path, v1BrokenLink)
	assertDirNames(t, dir, "config.yaml")
	if !strings.Contains(logs.String(), "configuration reset after upgrade") {
		t.Fatalf("reset log = %s", logs)
	}
	for _, secret := range []string{"fixture-secret", "example.net"} {
		if strings.Contains(stdout+stderr+logs.String(), secret) {
			t.Fatalf("%q disclosed: dry run %q %q, log %q", secret, stdout, stderr, logs)
		}
	}
}

func TestLoadOrResetMissingFileFails(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := loadOrReset(filepath.Join(dir, "config.yaml")); !errors.Is(err, fs.ErrNotExist) {
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

// The installer reports the access URL right after an upgrade, before any
// save: it comes from the address the reset keeps, and the file stays as is.
func TestURLAfterResetUsesTheKeptAddress(t *testing.T) {
	dir, path := writeConfigFile(t, v010Config)
	stdout, stderr, code := runKeenproxy(t, "--url", "-config", path)
	if code != 0 || stdout != "http://192.0.2.1:8086\n" {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
	assertFileBytes(t, path, v010Config)
	assertDirNames(t, dir, "config.yaml")
}

// startDaemon runs a daemon on cfg as main does, with test ports, without
// country databases and with a firewall that changes nothing.
func startDaemon(t *testing.T, path string, cfg *model.Config) *daemon.Daemon {
	t.Helper()
	limit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(limit) })
	cfg.DNS.Listen = "127.0.0.1:0"
	cfg.Intercept.TCPPort = freeTCPPort(t)
	for i := range cfg.GeoIP.Databases {
		cfg.GeoIP.Databases[i].Enabled = false
	}
	d := daemon.New(daemon.Options{
		ConfigPath:    path,
		Config:        cfg,
		RuleSetDir:    t.TempDir(),
		ARPPath:       filepath.Join(t.TempDir(), "arp"),
		Firewall:      &netfilter.Firewall{Run: noFirewall{}, IPTables: "iptables", Restore: "iptables-restore"},
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		WatchInterval: time.Hour,
		DeviceNames:   func(context.Context, map[string]netip.Addr) map[string]devices.Name { return nil },
		SingBoxLog:    os.DevNull,
	})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(15 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	for deadline := time.Now().Add(15 * time.Second); d.Status(context.Background()).DNS == ""; {
		select {
		case err := <-errc:
			t.Fatalf("daemon stopped during startup: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return d
}

// noFirewall accepts every command. It installs no rules, so a deletion
// reports that none remain.
type noFirewall struct{}

func (noFirewall) Run(_ context.Context, _, _ string, args ...string) error {
	if slices.Contains(args, "-D") {
		return errors.New("rule absent")
	}
	return nil
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
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
