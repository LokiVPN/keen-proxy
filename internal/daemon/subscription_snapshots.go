package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

// subscriptionSnapshot is the private, last activated provider state. Probe
// health and failed fetch attempts are transient; a successful selection survives reboot.
type subscriptionSnapshot struct {
	Nodes       []subscription.Node   `json:"nodes"`
	Metadata    subscription.Metadata `json:"metadata"`
	Skipped     int                   `json:"skipped,omitempty"`
	LastSuccess time.Time             `json:"last_success"`
	Selection   subscriptionSelection `json:"selection"`
	// Rules exists only for the source named by provider_rules.
	Rules *rulesSnapshot `json:"rules,omitempty"`
}

type subscriptionSelection struct {
	Node   string    `json:"node,omitempty"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason,omitempty"`
}

// subscriptionIdentity drops settings that do not change what is downloaded
// (the reserve), so editing them keeps the fetched list, health and selection.
// It must cover the same fields as the fingerprint.
func subscriptionIdentity(source subscription.Source) subscription.Source {
	source.Fallback = ""
	return source
}

func subscriptionFingerprint(source subscription.Source) string {
	digest := sha256.Sum256([]byte("keenproxy-subscription-v1\x00" + source.ID + "\x00" + source.URL + "\x00" + strconv.FormatBool(source.SendHWID)))
	return hex.EncodeToString(digest[:])
}

// The source-set path keeps the previously saved YAML recoverable if Apply
// publishes new snapshots and then fails or stops before publishing that YAML.
func (d *Daemon) subscriptionSnapshotPath(cfg *model.Config) string {
	keys := make([]string, 0, len(cfg.Subscriptions))
	for _, source := range cfg.Subscriptions {
		keys = append(keys, subscriptionFingerprint(source))
	}
	slices.Sort(keys)
	digest := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return filepath.Join(d.subscriptions.directory, "snapshots-"+hex.EncodeToString(digest[:])+".json")
}

// loadSubscriptionSnapshotsLocked restores validated snapshots matching the
// saved configuration before interception starts. Missing data remains pending.
func (d *Daemon) loadSubscriptionSnapshotsLocked(ctx context.Context, cfg *model.Config) {
	path := d.subscriptionSnapshotPath(cfg)
	d.subscriptions.savedPath = path
	if len(cfg.Subscriptions) == 0 {
		return
	}
	var snapshots map[string]subscriptionSnapshot
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 {
		raw, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(raw, &snapshots) != nil {
			d.audit("system", "Subscription snapshots unavailable", "subscriptions", "warn", "saved snapshots could not be read")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		d.audit("system", "Subscription snapshots unavailable", "subscriptions", "warn", "saved snapshots could not be opened privately")
	}

	states := make(map[string]appliedSubscription, len(cfg.Subscriptions))
	for _, source := range cfg.Subscriptions {
		state := appliedSubscription{source: source, probeEpoch: new(byte)}
		snapshot := snapshots[subscriptionFingerprint(source)]
		switch {
		case len(snapshot.Nodes) == 0 || snapshot.LastSuccess.IsZero():
		case !validSnapshotNodeIDs(snapshot.Nodes):
			d.audit("system", "Subscription snapshot rejected", source.ID, "warn", "saved node identities failed validation")
		default:
			nodes, skipped := supportedSubscriptionNodes(ctx, snapshot.Nodes)
			if len(nodes) > 0 {
				snapshot.Nodes, snapshot.Skipped = nodes, snapshot.Skipped+skipped
				if snapshot.Rules != nil && snapshot.Rules.Built != nil {
					snapshot.Rules.Built.MarkUnusableRules()
				}
				state.snapshot = snapshot
				state.recordAttempt(subscriptionAttempt{at: snapshot.LastSuccess, result: subscription.Result{
					State: subscription.StateReady,
				}})
			}
		}
		syncProviderRules(cfg, &state)
		states[source.ID] = state
	}
	d.subscriptions.states = states
}

// validSnapshotNodeIDs prevents a corrupted private file from rebinding a pin.
func validSnapshotNodeIDs(nodes []subscription.Node) bool {
	seen := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		if seen[node.ID] || !node.MatchesLink() {
			return false
		}
		seen[node.ID] = true
	}
	return true
}

// saveChangedSubscriptionSnapshotsLocked writes when a source set, usable list,
// selection or provider rules have changed during Apply; ordinary unrelated
// edits incur no write.
func (d *Daemon) saveChangedSubscriptionSnapshotsLocked(cfg *model.Config, previous map[string]appliedSubscription) error {
	if len(previous) != len(d.subscriptions.states) {
		return d.saveSubscriptionSnapshotsLocked(cfg)
	}
	for id, state := range d.subscriptions.states {
		old := previous[id]
		if subscriptionIdentity(old.source) != subscriptionIdentity(state.source) || old.snapshot.Selection != state.snapshot.Selection ||
			!old.snapshot.LastSuccess.Equal(state.snapshot.LastSuccess) || old.snapshot.Rules != state.snapshot.Rules {
			return d.saveSubscriptionSnapshotsLocked(cfg)
		}
	}
	return nil
}

// saveSubscriptionSnapshotsLocked publishes the whole activated source set in
// one rename. The temporary file is private and stays on the same filesystem.
func (d *Daemon) saveSubscriptionSnapshotsLocked(cfg *model.Config) error {
	snapshots := make(map[string]subscriptionSnapshot)
	for _, state := range d.subscriptions.states {
		if len(state.snapshot.Nodes) > 0 {
			snapshots[subscriptionFingerprint(state.source)] = state.snapshot
		}
	}
	if len(snapshots) == 0 {
		return nil
	}
	raw, err := json.Marshal(snapshots)
	if err != nil {
		return errSubscriptionSnapshot
	}
	path := d.subscriptionSnapshotPath(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errSubscriptionSnapshot
	}
	if err := d.warnDurability(replacePrivateFile(path, raw, d.log)); err != nil {
		return errSubscriptionSnapshot
	}
	return nil
}

// retainSavedSubscriptionSnapshotsLocked runs only after YAML publication. The
// prior saved bundle still matches config.yaml.previous even after an unsaved Apply.
func (d *Daemon) retainSavedSubscriptionSnapshotsLocked(cfg *model.Config) {
	current, previous := d.subscriptionSnapshotPath(cfg), d.subscriptions.savedPath
	d.subscriptions.savedPath = current
	if previous == "" {
		return
	}
	entries, err := os.ReadDir(d.subscriptions.directory)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		match, ok := strings.CutPrefix(name, "snapshots-")
		if !ok || !entry.Type().IsRegular() {
			continue
		}
		digest, found := strings.CutSuffix(match, ".json")
		if !found || len(digest) != 2*sha256.Size {
			continue
		}
		if _, decode := hex.DecodeString(digest); decode != nil {
			continue
		}
		path := filepath.Join(d.subscriptions.directory, name)
		if path != current && path != previous {
			err = errors.Join(err, os.Remove(path))
		}
	}
	if err != nil {
		d.audit("system", "Subscription snapshots could not be pruned", "subscriptions", "warn", "obsolete snapshots could not be removed")
	}
}
