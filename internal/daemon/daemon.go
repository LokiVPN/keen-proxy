// Package daemon coordinates configuration, compilation, sing-box, DNS, and
// firewall lifecycle. Its watchdog restores runtime state, while Apply updates
// configuration and restarts only components whose inputs changed.
package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/devices"
	"github.com/ordo-systems/keen-proxy/internal/dnsfront"
	"github.com/ordo-systems/keen-proxy/internal/domaincache"
	"github.com/ordo-systems/keen-proxy/internal/engine"
	"github.com/ordo-systems/keen-proxy/internal/geoip"
	"github.com/ordo-systems/keen-proxy/internal/journal"
	"github.com/ordo-systems/keen-proxy/internal/lists"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/netfilter"
	"github.com/ordo-systems/keen-proxy/internal/stats"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// Options supplies local paths, runtime dependencies, and watchdog settings.
type Options struct {
	ConfigPath string
	// Config is the configuration Run starts with; nil loads ConfigPath. The
	// caller may have reset an older file in memory: ConfigPath changes only
	// when a configuration is saved, and that first save keeps a file older
	// releases read as config.v1.yaml.
	Config        *model.Config
	ARPPath       string        // /proc/net/arp
	RuleSetDir    string        // local sing-box client address rule-sets
	WatchInterval time.Duration // watchdog interval for firewall and neighbor checks
	Firewall      *netfilter.Firewall
	Log           *slog.Logger
	Journals      journal.Set                                                          // nil creates in-memory journals
	SingBoxLog    string                                                               // sing-box log destination (see engine.LogOutput)
	DeviceNames   func(context.Context, map[string]netip.Addr) map[string]devices.Name // optional local name source
	// OnStartupBlocked runs under the daemon lock once management-only startup
	// is initialized. It must return promptly without calling daemon methods.
	OnStartupBlocked func()
	// OnStartupActive runs under the daemon lock after the initial apply in Run,
	// not after a later Apply or recovery. It must return promptly without calling daemon methods.
	OnStartupActive func()
}

// Daemon owns runtime components and coordinates serialized configuration changes.
type Daemon struct {
	domainGeneration atomic.Pointer[domainGeneration]
	dnsRouteMu       sync.Mutex
	dnsRoute         string // latest DNS route, to journal fallback transitions
	domains          *domaincache.Cache
	domainSlots      chan struct{}
	domainError      string
	dnsFiles         dnsFiles // protected by mu
	opt              Options
	log              *slog.Logger
	tproxyProbe      func(context.Context) netfilter.TProxyReadiness

	// startupBlocked is protected by mu and closed on first successful activation.
	startupBlocked chan struct{}

	mu           sync.Mutex // serializes apply and protects runtime state below, except atomic live
	runCtx       context.Context
	closed       bool
	cfg          *model.Config
	eng          engine.Engine
	dns          *dnsfront.Server
	route        netfilter.TProxyRoute
	routeOn      bool
	routeRelease func() error // ownership-aware cleanup for a recovered TPROXY route
	plan         netfilter.Plan
	planOn       bool
	planPending  bool // installation failed after the plan and its dependencies were prepared
	neighbors    map[string]netip.Addr
	deviceNames  map[string]cachedDeviceName
	started      time.Time
	restored     int // number of watchdog firewall restorations
	stats        *stats.Tracker
	geo          geoState

	subscriptions subscriptionRuntime

	neighborUpdatePending bool // a failed compile may have written only some rule-sets

	// geoStore owns downloaded IP databases; geoWake triggers a check.
	geoStore *geoip.Store
	geoWake  chan struct{}
	// firewallWake coalesces external checks; the watchdog remains the sole consumer.
	firewallWake chan struct{}
	// serverHosts maps connection IDs to server hosts from the latest compilation.
	serverHosts map[string]string
	journals    journal.Set
	// live publishes the current configuration to route logging without d.mu.
	live atomic.Pointer[model.Config]
	// dnsNames publishes the DNS names of the applied configuration and
	// provider rules to the DNS frontend's goroutines, which must not take
	// d.mu. Only dnsNamesLocked stores it.
	dnsNames atomic.Pointer[dnsNamesState]
	// split publishes which devices follow split policies, from the latest
	// compilation, to the DNS frontend's goroutines. Only compileLocked
	// stores it.
	split atomic.Pointer[compile.SplitAddresses]
	// coreRestarted records whether the latest applyLocked restarted the engine.
	coreRestarted bool
	// memoryBaseline is the process limit captured before configuration is applied.
	memoryBaseline int64
	// memoryDefault honors the startup limit, falling back to 768 MiB when unset.
	memoryDefault int64
	// memoryActive is the limit from the last successful activation.
	memoryActive int64
	// configCurrent records that ConfigPath holds the current schema because
	// this daemon saved it. Until then a save checks whether the file is one
	// older releases read and keeps it first.
	configCurrent bool
	// Fallback chains, selected members, and probe results from the latest
	// compilation (see failover.go).
	chains  []compile.FailoverChain
	active  map[string]string
	health  map[string]*health
	allDown map[string]bool
}

// New creates a daemon with default paths and in-memory journals when omitted.
// It captures the current process memory limit and does not start listeners
// or install interception rules.
func New(opt Options) *Daemon {
	baseline := debug.SetMemoryLimit(-1)
	memoryDefault := baseline
	if baseline == math.MaxInt64 && os.Getenv("GOMEMLIMIT") == "" {
		memoryDefault = 768 * 1024 * 1024
	}
	if opt.DeviceNames == nil {
		opt.DeviceNames = devices.NewNameLookup()
	}
	if opt.WatchInterval == 0 {
		opt.WatchInterval = 30 * time.Second
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.RuleSetDir == "" {
		opt.RuleSetDir = "/opt/var/lib/keenproxy/rule-sets"
	}
	if opt.Journals == nil {
		opt.Journals = journal.NewSet("")
	}
	d := &Daemon{
		domains: domaincache.New(time.Now), domainSlots: make(chan struct{}, 4), opt: opt, log: opt.Log, stats: stats.NewTracker(), journals: opt.Journals,
		active: map[string]string{}, health: map[string]*health{}, allDown: map[string]bool{},
	}
	d.tproxyProbe = opt.Firewall.TProxyReadiness
	d.memoryBaseline = baseline
	d.memoryDefault = memoryDefault
	d.memoryActive = baseline
	d.geoStore = geoip.NewStore(filepath.Join(filepath.Dir(opt.RuleSetDir), "geoip"))
	d.geoWake = make(chan struct{}, 1)
	d.subscriptions = newSubscriptionRuntime(opt.RuleSetDir)
	d.firewallWake = make(chan struct{}, 1)
	d.resetDomainGeneration()
	d.stats.OnRoute = d.onRoute
	d.eng.Tracker = d.stats
	d.eng.LogOutput = opt.SingBoxLog
	return d
}

// Run serves until ctx is canceled. Interception starts last and stops first
// so clients retain access to a DNS resolver during lifecycle transitions.
func (d *Daemon) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.runCtx != nil || d.closed {
		d.mu.Unlock()
		return errors.New("daemon cannot run more than once")
	}
	d.runCtx = ctx
	defer d.shutdown()
	activated, err := func() (<-chan struct{}, error) {
		defer d.mu.Unlock()
		activated, err := d.startLocked(ctx)
		if err != nil {
			d.closed = true
		}
		return activated, err
	}()
	if err != nil {
		d.audit("system", "Start keenProxy", "core", "error", err.Error())
		return err
	}
	go d.stats.Run(ctx)
	if activated != nil {
		// The API can activate interception by applying a configuration while Run waits.
		select {
		case <-activated:
		case <-ctx.Done():
		}
	}
	if ctx.Err() == nil {
		go d.runGeoUpdates(ctx)
		go d.runFailover(ctx)
		go d.runSubscriptions(ctx)
		go d.runSubscriptionHealth(ctx)
		go d.runDomains(ctx)
		go d.runDeviceNames(ctx)
		d.runWatchdog(ctx)
	}
	d.log.Info("stopping keenProxy")
	d.audit("system", "Stop keenProxy", "core", "info", "interception rules removed, network uses direct routing")
	return nil
}

func (d *Daemon) startLocked(ctx context.Context) (<-chan struct{}, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	cfg := d.opt.Config
	if cfg == nil {
		var err error
		if cfg, err = model.Load(d.opt.ConfigPath); err != nil {
			return nil, err
		}
	}
	d.started = time.Now()
	blocked := d.tproxyPreflight(ctx, cfg)
	if ctx.Err() != nil {
		return nil, nil
	}
	// Apply the saved recommendation before geo databases and the embedded core start.
	if blocked == nil {
		if err := d.stageMemoryLimit(cfg); err != nil {
			return nil, err
		}
	}
	d.loadSubscriptionSnapshotsLocked(ctx, cfg)
	d.adoptLegacyGeo(cfg)
	d.reloadGeoLocked(cfg)
	d.neighbors = d.readNeighbors(cfg)
	if blocked != nil {
		d.stopInterceptionLocked()
		if err := d.detachStartupJumps(); err != nil {
			return nil, fmt.Errorf("detach residual interception rules: %w", err)
		}
		if ctx.Err() != nil {
			return nil, nil
		}
		d.startupBlocked = make(chan struct{})
		d.cfg = cfg
		d.live.Store(cfg)
		d.log.Warn("keenProxy started without interception", "err", blocked)
		d.audit("system", "Start keenProxy without interception", "core", "warn", blocked.Error())
		if d.opt.OnStartupBlocked != nil {
			d.opt.OnStartupBlocked()
		}
		return d.startupBlocked, nil
	}
	before := maps.Clone(d.subscriptions.states)
	if err := d.applyLocked(ctx, cfg); err != nil {
		return nil, err
	}
	d.stats.RetainSubscriptionNodes(d.subscriptions.members)
	if err := d.saveChangedSubscriptionSnapshotsLocked(cfg, before); err != nil {
		d.audit("system", "Subscription selection not saved", "subscriptions", "warn", err.Error())
	}
	d.auditSubscriptionSelectionsLocked(before)
	d.log.Info("keenProxy started", "mode", cfg.Intercept.Mode, "sources", len(d.plan.Sources), "dns", d.dns.Addr())
	d.audit("system", "Start keenProxy", "core", "ok",
		fmt.Sprintf("interception %s, sources %d, DNS %s", cfg.Intercept.Mode, len(d.plan.Sources), d.dns.Addr()))
	if ctx.Err() == nil && d.opt.OnStartupActive != nil {
		d.opt.OnStartupActive()
	}
	return nil, nil
}

// Apply validates, applies, and persists configuration. Recovery from blocked
// startup commits only after saving; an already-active daemon can report an
// applied-but-unsaved change.
func (d *Daemon) Apply(ctx context.Context, cfg *model.Config) error {
	by, from := applyActor(ctx)
	cfg.Defaults()
	if err := cfg.Validate(); err != nil {
		d.audit(by, "Configuration rejected", "config", "error", err.Error()+from)
		return err
	}
	// Apply saves the configuration, and saves use the current schema.
	cfg.SchemaVersion = model.SchemaVersion
	// Compile first so protocol errors do not disturb the running configuration.
	if _, err := compile.Compile(compile.Input{Config: cfg, RuleSetDir: d.opt.RuleSetDir}); err != nil {
		d.audit(by, "Configuration rejected", "config", "error", err.Error()+from)
		return err
	}
	return d.applyWithSubscriptions(ctx, cfg)
}

func applyActor(ctx context.Context) (by, from string) {
	who := actorOf(ctx)
	if who.From != "" {
		from = " (from " + who.From + ")"
	}
	return who.Who, from
}

func (d *Daemon) applyAdmissionLocked(ctx context.Context) error {
	if d.closed || (d.runCtx != nil && d.runCtx.Err() != nil) {
		return errors.New("daemon is stopping")
	}
	return ctx.Err()
}

// applyConfigLocked is shared by draft Apply and saved recovery.
func (d *Daemon) applyConfigLocked(ctx context.Context, cfg *model.Config, save bool, candidates map[subscription.Source]subscriptionAttempt) error {
	if err := d.applyAdmissionLocked(ctx); err != nil {
		return err
	}
	by, from := applyActor(ctx)
	if err := d.tproxyPreflight(ctx, cfg); err != nil {
		d.audit(by, "Configuration rejected", "config", "error", err.Error()+from)
		return err
	}
	if err := d.applyAdmissionLocked(ctx); err != nil {
		return err
	}
	prev := d.cfg
	changes := configChanges(prev, cfg)
	activation := d.startupBlocked
	neighbors := d.neighbors
	previousSubscriptions := d.subscriptions.states
	previousHealth := d.health
	if len(previousSubscriptions) > 0 || len(cfg.Subscriptions) > 0 {
		previousHealth = maps.Clone(d.health)
	}
	restoreBalanceSessions := d.eng.SubscriptionBalanceCheckpoint()
	d.subscriptions.states = d.subscriptionDraftLocked(cfg, candidates)
	d.discardReplacedSubscriptionHealthLocked(previousSubscriptions)
	err := d.applyLocked(ctx, cfg)
	if err == nil {
		err = d.saveChangedSubscriptionSnapshotsLocked(cfg, previousSubscriptions)
	}
	if err != nil {
		restoreBalanceSessions()
		d.subscriptions.states, d.health = previousSubscriptions, previousHealth
		details := err.Error()
		restore := journalRestoreFailure(err)
		var rollbackRestore *journal.RestoreDiagnostic
		if activation != nil {
			d.log.Error("configuration failed to activate, interception remains inactive", "err", err)
			d.restoreInactiveLocked(prev)
			d.neighbors = neighbors
			details += "; interception remains inactive"
		} else if prev != nil {
			d.log.Error("new configuration failed to apply, restoring previous configuration", "err", err)
			if rbErr := d.applyLocked(ctx, prev); rbErr != nil {
				d.log.Error("rollback also failed", "err", rbErr)
				details += "; rollback also failed: " + rbErr.Error()
				rollbackRestore = journalRestoreFailure(rbErr)
			} else {
				details += "; previous configuration restored"
			}
		} else {
			d.restoreInactiveLocked(nil)
		}
		entry := journal.Entry{Actor: by, Action: "Configuration apply failed", Target: "config", Result: "error", Details: details + from}
		if restore != nil || rollbackRestore != nil {
			entry.FirewallApply = &journal.FirewallApplyDiagnostic{Restore: restore, RollbackRestore: rollbackRestore}
		}
		d.auditEntry(entry)
		return err
	}
	if activation != nil {
		err := d.applyAdmissionLocked(ctx)
		if err == nil && save {
			err = d.persistConfig(cfg, true)
		}
		if err != nil {
			restoreBalanceSessions()
			d.subscriptions.states, d.health = previousSubscriptions, previousHealth
			d.restoreInactiveLocked(prev)
			d.neighbors = neighbors
			d.audit(by, "Configuration apply failed", "config", "error", err.Error()+"; interception remains inactive"+from)
			return err
		}
		d.commitMemoryLimit(cfg)
		d.live.Store(cfg)
		d.startupBlocked = nil
		close(activation)
	}
	d.stats.RetainSubscriptionNodes(d.subscriptions.members)
	if activation == nil && save {
		if err := d.persistConfig(cfg, false); err != nil {
			d.auditSubscriptionSelectionsLocked(previousSubscriptions)
			wakeSubscriptionWorker(d.subscriptions.wake)
			d.audit(by, "Configuration applied but not saved", "config", "warn", err.Error()+from)
			return fmt.Errorf("configuration applied but not saved: %w", err)
		}
	}
	if save {
		d.retainSavedSubscriptionSnapshotsLocked(cfg)
	}
	d.auditSubscriptionSelectionsLocked(previousSubscriptions)
	for source := range candidates {
		delete(d.subscriptions.previews, source)
	}
	if len(cfg.Subscriptions) > 0 {
		wakeSubscriptionWorker(d.subscriptions.wake)
		if prev != nil && prev.Failover != cfg.Failover {
			wakeSubscriptionWorker(d.subscriptions.probeWake)
		}
	}
	action := "Apply configuration"
	if save {
		d.log.Info("configuration applied and saved")
	} else {
		action = "Activate saved configuration"
		d.log.Info("saved configuration activated")
	}
	core := "core not restarted"
	if d.coreRestarted {
		core = "core restarted"
	}
	d.audit(by, action, "config", "ok", changes+"; "+core+from)
	if prev == nil || !reflect.DeepEqual(prev.GeoIP, cfg.GeoIP) {
		// New or re-enabled databases download without waiting for the next check.
		d.wakeGeo()
	}
	go d.refreshConnCountries(context.Background())
	return nil
}

// persistConfig saves cfg at ConfigPath while d.mu is held. Until the daemon
// has saved the file once, it first keeps a file older releases read (see
// keepV1Config); afterwards the file is known to be current and is not parsed
// again. The replaced bytes become config.yaml.previous.
func (d *Daemon) persistConfig(cfg *model.Config, recovery bool) error {
	raw, err := cfg.Marshal()
	if err != nil {
		return err
	}
	previous, err := os.ReadFile(d.opt.ConfigPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// What the save would replace is unknown, so it cannot be backed up.
		return fmt.Errorf("current configuration could not be read: %w", err)
	}
	if err == nil {
		if !d.configCurrent {
			backup, err := keepV1Config(d.opt.ConfigPath, previous, d.log)
			if err != nil {
				return err
			}
			if backup != "" {
				d.log.Info("configuration for older releases kept", "backup", backup)
			}
		}
		if recovery {
			if err := d.warnDurability(persistRecoveryConfig(d.opt.ConfigPath, previous, raw, d.log)); err != nil {
				return err
			}
			d.configCurrent = cfg.SchemaVersion >= model.SchemaVersion
			return nil
		}
		if err := d.warnDurability(replacePrivateFile(d.opt.ConfigPath+".previous", previous, d.log)); err != nil {
			return fmt.Errorf("previous configuration was not saved: %w", err)
		}
	} else if recovery {
		return fmt.Errorf("previous configuration could not be read: %w", err)
	}
	if err := d.warnDurability(replacePrivateFile(d.opt.ConfigPath, raw, d.log)); err != nil {
		return fmt.Errorf("configuration was not saved: %w", err)
	}
	d.configCurrent = cfg.SchemaVersion >= model.SchemaVersion
	return nil
}

// persistRecoveryConfig stages the main YAML before publishing its backup.
// If the final rename fails, the original rollback snapshot can be restored
// without allocating disk space. Ordinary active applies replace each file in
// turn and report a failure without restoring the other. A directory sync
// failure after the last rename is a durabilityError.
func persistRecoveryConfig(path string, original, next []byte, log *slog.Logger) error {
	mainChanged := !bytes.Equal(original, next)
	var mainTemp string
	if mainChanged {
		var err error
		mainTemp, err = stagePrivateFile(path, next)
		if err != nil {
			return fmt.Errorf("configuration was not saved: %w", err)
		}
		defer os.Remove(mainTemp)
	}

	previousPath := path + ".previous"
	previous, err := os.ReadFile(previousPath)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return fmt.Errorf("rollback snapshot could not be read: %w", err)
	}
	previousChanged := missing || !bytes.Equal(previous, original)
	var rollbackTemp string
	if previousChanged {
		if mainChanged && !missing {
			rollbackTemp, err = stagePrivateFile(previousPath+".recovery", previous)
			if err != nil {
				return fmt.Errorf("rollback snapshot was not saved: %w", err)
			}
			defer func() {
				if rollbackTemp != "" {
					os.Remove(rollbackTemp)
				}
			}()
		}
		previousTemp, err := stagePrivateFile(previousPath, original)
		if err != nil {
			return fmt.Errorf("previous configuration was not saved: %w", err)
		}
		defer os.Remove(previousTemp)
		if err := os.Rename(previousTemp, previousPath); err != nil {
			return fmt.Errorf("previous configuration was not saved: %w", err)
		}
	}

	if !mainChanged {
		if previousChanged {
			if err := syncDir(filepath.Dir(path), log); err != nil {
				return &durabilityError{err}
			}
		}
		return nil
	}
	if err := os.Rename(mainTemp, path); err != nil {
		saveErr := fmt.Errorf("configuration was not saved: %w", err)
		if previousChanged {
			if missing {
				if err := os.Remove(previousPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return errors.Join(saveErr, fmt.Errorf("rollback snapshot could not be removed: %w", err))
				}
			} else if err := os.Rename(rollbackTemp, previousPath); err != nil {
				preserved := rollbackTemp
				rollbackTemp = "" // Keep the distinct snapshot available for manual recovery.
				return errors.Join(saveErr, fmt.Errorf("could not restore rollback snapshot from %s: %w", preserved, err))
			}
		}
		return saveErr
	}
	if err := syncDir(filepath.Dir(path), log); err != nil {
		return &durabilityError{err}
	}
	return nil
}

// durabilityError reports that a file was replaced but its directory entry
// may not survive a crash. The save counts as done; callers log a warning.
type durabilityError struct{ err error }

func (e *durabilityError) Error() string { return "directory sync failed: " + e.err.Error() }
func (e *durabilityError) Unwrap() error { return e.err }

// warnDurability logs and drops a durabilityError and passes other errors on.
func (d *Daemon) warnDurability(err error) error {
	var de *durabilityError
	if errors.As(err, &de) {
		d.log.Warn("configuration saved, but its directory could not be synced", "err", de.err)
		return nil
	}
	return err
}

// replacePrivateFile atomically replaces path with a mode 0600 file holding
// data and leaves a file that already holds data alone. The data is synced
// before the rename and the directory after it, so after a crash path holds
// the old or the new bytes. The daemon writes its configuration, the
// configuration's rollback copy and subscription snapshots this way.
func replacePrivateFile(path string, data []byte, log *slog.Logger) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	temp, err := stagePrivateFile(path, data)
	if err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	if err := syncDir(filepath.Dir(path), log); err != nil {
		return &durabilityError{err}
	}
	return nil
}

// stagePrivateFile writes data to a new synced mode 0600 file beside path and
// returns its name. The caller renames it into place or removes it.
func stagePrivateFile(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err := errors.Join(err, f.Close()); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// fsyncDir flushes an open directory; tests replace it.
var fsyncDir = func(f *os.File) error { return f.Sync() }

// syncDir makes entries created or renamed in dir durable. Filesystems that
// cannot fsync a directory (EINVAL, ENOTSUP) are tolerated with a warning on
// log, the daemon's logger, so it reaches the system journal.
func syncDir(dir string, log *slog.Logger) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = fsyncDir(f)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		log.Warn("directory sync is not supported here; durability after a crash is not guaranteed", "dir", dir)
		err = nil
	}
	return errors.Join(err, f.Close())
}

// applyLocked reconciles runtime state with cfg while d.mu is held.
func (d *Daemon) applyLocked(ctx context.Context, cfg *model.Config) error {
	prev := d.cfg
	if d.startupBlocked != nil {
		d.neighbors = d.readNeighbors(cfg)
	}
	// A new attempt may change the old plan's dependencies before it reaches iptables.
	d.planPending = false
	if err := d.stageMemoryLimit(cfg); err != nil {
		return err
	}
	applied := false
	defer func() {
		if !applied {
			debug.SetMemoryLimit(d.memoryActive)
		}
	}()
	d.resetDomainGeneration()
	if prev != nil && !reflect.DeepEqual(prev.GeoIP, cfg.GeoIP) {
		d.reloadGeoLocked(cfg)
	}
	d.cfg = cfg
	if d.startupBlocked == nil {
		d.live.Store(cfg)
	}
	d.coreRestarted = false
	out, err := d.compileLocked()
	if err != nil {
		return err
	}
	d.warnDroppedProviderEntries(out)
	restarted, err := d.applyCoreLocked(out)
	if err != nil {
		return err
	}
	if restarted && prev != nil && d.startupBlocked == nil {
		d.coreRestarted = true
		d.log.Info("sing-box core restarted with new configuration")
	}
	if d.dns == nil || prev == nil || dnsFrontendChanged(prev.DNS, cfg.DNS) || dnsGroupsChanged(prev.Groups, cfg.Groups) {
		if d.dns != nil {
			d.dns.Close()
			d.dns = nil
		}
		if err := d.startDNS(); err != nil {
			return fmt.Errorf("DNS: %w", err)
		}
	}

	newRoute := netfilter.TProxyRoute{Mark: cfg.Intercept.FWMark, Table: cfg.Intercept.RouteTable}
	wantRoute := cfg.Intercept.Mode == model.InterceptTProxy
	if d.routeOn && (!wantRoute || newRoute != d.route) {
		d.removeRouteLocked()
	}
	if wantRoute && !d.routeOn {
		var err error
		if d.startupBlocked != nil {
			d.routeRelease, err = newRoute.Acquire()
		} else {
			err = newRoute.Apply()
		}
		if err != nil {
			return err
		}
		d.routeOn = true
	}
	d.route = newRoute

	// Interception mode changes require removing the complete previous chain set.
	if d.planOn && d.plan.Mode != out.Plan.Mode {
		d.removeFirewall()
	}
	d.plan = out.Plan
	if err := d.installFirewall(ctx); err != nil {
		if d.startupBlocked == nil {
			d.removeFirewall()
			d.planPending = true
		}
		return fmt.Errorf("interception rules: %w", err)
	}
	if d.startupBlocked == nil {
		d.commitMemoryLimit(cfg)
	}
	applied = true
	return nil
}

// dnsFrontendChanged ignores the firewall-only source exemptions.
func dnsFrontendChanged(prev, next model.DNS) bool {
	prev.BypassSources, next.BypassSources = nil, nil
	// The serialized config can contain an empty list for omitted upstreams.
	if len(prev.Upstreams) == 0 && len(next.Upstreams) == 0 {
		prev.Upstreams, next.Upstreams = nil, nil
	}
	return !reflect.DeepEqual(prev, next)
}

// dnsGroupsChanged treats the empty lists inserted by the panel as omissions.
func dnsGroupsChanged(prev, next []model.Group) bool {
	return !slices.EqualFunc(prev, next, func(a, b model.Group) bool {
		if len(a.Entries) == 0 && len(b.Entries) == 0 {
			a.Entries, b.Entries = nil, nil
		}
		return reflect.DeepEqual(a, b)
	})
}

// shutdown removes interception before stopping the services it depends on
// and restores the process memory limit captured at initialization.
func (d *Daemon) shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if g := d.domainGeneration.Load(); g != nil {
		g.cancel()
	}
	d.stopInterceptionLocked()
	d.geo.set.Close()
	d.geo.cats.Close()
	d.geo.set, d.geo.cats = nil, nil
	debug.SetMemoryLimit(d.memoryBaseline)
	d.memoryActive = d.memoryBaseline
}

// stopInterceptionLocked detaches firewall and routing state before closing listeners.
func (d *Daemon) stopInterceptionLocked() {
	if d.planOn || d.planPending {
		d.removeFirewall()
	}
	d.removeRouteLocked()
	if d.dns != nil {
		d.dns.Close()
		d.dns = nil
	}
	d.eng.Close()
}

func (d *Daemon) removeRouteLocked() {
	if !d.routeOn {
		return
	}
	release := d.routeRelease
	if release == nil {
		release = d.route.Remove
	}
	if err := release(); err != nil {
		d.log.Warn("remove TPROXY route", "err", err)
	}
	d.routeOn, d.routeRelease = false, nil
}

// restoreInactiveLocked tears down a failed first activation without activating
// the saved configuration that was intentionally skipped at startup.
func (d *Daemon) restoreInactiveLocked(cfg *model.Config) {
	d.stopInterceptionLocked()
	debug.SetMemoryLimit(d.memoryActive)
	d.plan = netfilter.Plan{}
	if cfg != nil && !reflect.DeepEqual(d.cfg.GeoIP, cfg.GeoIP) {
		d.reloadGeoLocked(cfg)
	}
	d.cfg = cfg
	d.chains, d.serverHosts = nil, nil
	d.subscriptions.selectors, d.subscriptions.balances, d.subscriptions.members = nil, nil, nil
	d.subscriptions.generation++
	if cfg != nil {
		d.reselectLocked()
	} else {
		d.live.Store(nil)
	}
	d.resetDomainGeneration()
}

// stageMemoryLimit applies cfg's recommendation, or the selected startup/default budget when unset.
// A rejected value is not forwarded to the runtime. Success is recorded only by commitMemoryLimit.
func (d *Daemon) stageMemoryLimit(cfg *model.Config) error {
	limit, ok := model.MemoryLimitBytes(cfg, d.memoryDefault)
	if !ok {
		return fmt.Errorf("system.memory_limit_mib: value cannot be applied")
	}
	debug.SetMemoryLimit(limit)
	return nil
}

// commitMemoryLimit records the recommendation after activation succeeds.
func (d *Daemon) commitMemoryLimit(cfg *model.Config) {
	if limit, ok := model.MemoryLimitBytes(cfg, d.memoryDefault); ok {
		d.memoryActive = limit
	}
}

// startDNS installs runtime matchers and opens both DNS transports before interception.
func (d *Daemon) startDNS() error {
	var blocks []model.Group
	for _, g := range d.cfg.Groups {
		if !g.Disabled && g.Target == model.TargetBlock {
			blocks = append(blocks, g)
		}
	}
	m := lists.New(blocks)
	cfg := d.dnsConfig(d.cfg.DNS)
	cfg.Observe = d.observeDomain
	cfg.DropAAAA = true
	cfg.Blocked = func(name string) bool { return m.Domain(name) != lists.NoMatch }
	canary := d.cfg.DNS.FirefoxCanary
	cfg.BlockReason = func(name string, client netip.Addr) string {
		if canary && strings.EqualFold(strings.TrimSuffix(name, "."), "use-application-dns.net") {
			return "firefox-canary"
		}
		if d.providerBlocked(name, client) {
			return "provider"
		}
		return ""
	}
	cfg.OnRoute = d.recordDNSRoute
	cfg.OnBlock = d.recordDNSBlock
	d.dns = dnsfront.New(cfg)
	return d.dns.Start()
}

// watch refreshes neighbor addresses and restores missing interception rules.
func (d *Daemon) watch(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ctx.Err() != nil || (!d.planOn && !d.planPending) {
		return
	}
	if n := d.readNeighbors(d.cfg); d.neighborUpdatePending || !maps.Equal(n, d.neighbors) {
		previous := d.neighbors
		d.neighbors = n
		out, err := d.compileLocked()
		if err != nil {
			d.neighbors = previous
			d.neighborUpdatePending = true
			d.log.Error("recompile", "err", err)
			return
		}
		d.neighborUpdatePending = false
		if !maps.Equal(previous, n) {
			d.audit("watchdog", "Device addresses updated", "clients", "info", neighborsChange(previous, n))
		}
		// Client addresses live in watched rule-set files, so sing-box can
		// pick up changes without restarting.
		if restarted, err := d.applyCoreLocked(out); err != nil {
			d.log.Error("restart sing-box", "err", err)
		} else if restarted {
			d.log.Warn("sing-box configuration changed after address updates, core restarted")
		}
		d.plan = out.Plan
		if !d.planPending {
			if err := d.installFirewall(ctx); err != nil && ctx.Err() == nil {
				d.log.Error("rule update", "err", err)
			}
			return
		}
	}
	d.checkFirewall(ctx, "watchdog")
}

// applyCoreLocked activates compiled outbounds and restores runtime selections.
func (d *Daemon) applyCoreLocked(out compile.Output) (bool, error) {
	restarted, err := d.eng.Apply(out.SingBox)
	if err != nil {
		return false, err
	}
	if err := d.restoreSubscriptionSelectorsLocked(out, restarted, time.Now()); err != nil {
		return restarted, err
	}
	d.reselectLocked()
	return restarted, nil
}

func (d *Daemon) compileRuntimeLocked() (compile.Output, error) {
	return compile.Compile(compile.Input{
		Config: d.cfg, Neighbors: d.neighbors, RuleSetDir: d.opt.RuleSetDir,
		Subscriptions: d.subscriptionCompileInputLocked(),
		ProviderRules: d.providerRulesLocked(),
	})
}

// compileLocked compiles configuration and writes local rule-sets while d.mu
// is held. sing-box loads the files at startup and watches subsequent changes.
func (d *Daemon) compileLocked() (compile.Output, error) {
	out, err := d.compileRuntimeLocked()
	if err != nil {
		return out, err
	}
	if err := os.MkdirAll(d.opt.RuleSetDir, 0o755); err != nil {
		return out, err
	}
	for name, raw := range out.RuleSets {
		if strings.HasPrefix(name, "dns-") {
			continue
		}
		if err := writeFile(filepath.Join(d.opt.RuleSetDir, name), raw, 0o644); err != nil {
			return out, err
		}
	}
	if err := d.writeCountrySetsLocked(out.Countries); err != nil {
		return out, err
	}
	if err := d.writeCategorySetsLocked(out.Categories); err != nil {
		return out, err
	}
	d.writeDNSLocked()
	if d.domainError != "" {
		return out, fmt.Errorf("DNS rule-sets: %s", d.domainError)
	}
	d.serverHosts = out.ServerHosts
	d.chains = out.Failover
	d.split.Store(&out.Split)
	return out, nil
}

// writeFile atomically replaces a file through a temporary file and rename.
// Identical contents are left untouched to avoid unnecessary watcher reloads.
func writeFile(path string, data []byte, perm os.FileMode) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return replaceFile(path, data, perm)
}

// replaceFile atomically replaces a file through a temporary file and rename.
func replaceFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readNeighbors builds the MAC-to-IP snapshot for the configured LAN interface.
func (d *Daemon) readNeighbors(cfg *model.Config) map[string]netip.Addr {
	n, err := devices.ReadARP(d.opt.ARPPath, cfg.LAN.Interface)
	if err != nil {
		d.log.Warn("ARP unavailable, clients without static IP are excluded", "err", err)
		return map[string]netip.Addr{}
	}
	return n
}

// removeFirewall removes active interception rules using a fresh bounded context.
func (d *Daemon) removeFirewall() {
	// Use a fresh context because cleanup must run after the serving context is canceled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.opt.Firewall.Remove(ctx, d.plan); err != nil && !errors.Is(err, context.Canceled) {
		d.log.Warn("remove rules", "err", err)
	}
	d.planOn, d.planPending = false, false
}

// Config returns a deep copy of the current configuration.
func (d *Daemon) Config() *model.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil {
		return nil
	}
	return d.cfg.Clone()
}

// Status summarizes daemon, engine, interception, and connection health for the API.
type Status struct {
	Started       time.Time `json:"started"`
	Mode          string    `json:"mode"`
	Sources       int       `json:"sources"`
	Connections   int       `json:"connections"`
	Groups        int       `json:"groups"`
	Entries       int       `json:"entries"`
	Clients       int       `json:"clients"`
	OnlineDevices int       `json:"online_devices"`
	DNS           string    `json:"dns"`
	Firewall      bool      `json:"firewall"`
	Restored      int       `json:"restored"`
	GeoIP         GeoInfo   `json:"geoip"`
	// ConnCountries maps connection IDs to server country codes for flags.
	ConnCountries map[string]string `json:"conn_countries"`
	// Failover maps fallback-enabled connection IDs to their selected members.
	Failover map[string]FailoverInfo `json:"failover"`
	// Health maps connection IDs to their latest probe results.
	Health map[string]ConnHealth `json:"health"`
}

// Status snapshots runtime health under d.mu and checks active firewall entry jumps.
func (d *Daemon) Status(ctx context.Context) Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := Status{Started: d.started, Restored: d.restored, OnlineDevices: len(d.neighbors)}
	if d.cfg == nil {
		return st
	}
	st.Mode = string(d.cfg.Intercept.Mode)
	st.Sources = len(d.plan.Sources)
	st.Connections = len(d.cfg.Connections)
	st.Groups = len(d.cfg.Groups)
	st.Clients = len(d.cfg.Clients)
	for _, g := range d.cfg.Groups {
		st.Entries += len(g.Entries)
	}
	if d.dns != nil {
		st.DNS = d.dns.Addr()
	}
	st.Firewall = d.planOn && d.opt.Firewall.Healthy(ctx, d.plan)
	st.GeoIP = d.geoInfoLocked()
	st.ConnCountries = d.geo.conns
	st.Failover, st.Health = d.failoverInfoLocked()
	return st
}

// Stats returns connection traffic history and summaries.
func (d *Daemon) Stats(withSeries bool) stats.Snapshot { return d.stats.Snapshot(withSeries) }

// Hosts returns per-host traffic for one connection.
func (d *Daemon) Hosts(tag, query string, limit int) ([]stats.Host, int) {
	return d.stats.Hosts(tag, query, limit)
}

// Device combines an ARP neighbor, configured client identity, and observed hostname.
type Device struct {
	MAC            string     `json:"mac"`
	IP             string     `json:"ip"`
	Client         string     `json:"client,omitempty"` // configured client name
	Mode           model.Mode `json:"mode,omitempty"`
	Hostname       string     `json:"hostname,omitempty"`
	HostnameSource string     `json:"hostname_source,omitempty"`
}

// Devices merges current LAN neighbors with configured client names and identities.
func (d *Daemon) Devices() []Device {
	d.mu.Lock()
	defer d.mu.Unlock()
	known := map[string]model.Client{}
	if d.cfg != nil {
		for _, c := range d.cfg.Clients {
			if mac, err := net.ParseMAC(c.MAC); err == nil {
				known[mac.String()] = c
			}
		}
	}
	var out []Device
	for mac, ip := range d.neighbors {
		dev := Device{MAC: mac, IP: ip.String()}
		if cached, ok := d.deviceNames[mac]; ok && cached.ip == ip && time.Now().Before(cached.expires) {
			dev.Hostname, dev.HostnameSource = cached.name.Hostname, cached.name.Source
		}
		if c, ok := known[mac]; ok {
			dev.Client, dev.Mode = c.Name, c.Mode
		}
		out = append(out, dev)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		return a.Less(b)
	})
	return out
}
