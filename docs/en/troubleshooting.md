# Troubleshooting

## I edited a profile, but traffic did not change

On **Connections**, save changes on the connection's detail page. **Routing** and **Devices** each have their own **Save** button. On **Overview**, check that routing is enabled and the intended main connection is selected. Changes to those two controls apply immediately when JavaScript is available. A save that has started applying can finish after the connection to the panel drops. Reopen the page to see the applied settings, then test from an affected device and check the matching route. [Inspect local journals](#inspect-local-journals)

## HTTP passes but the application fails

Run HTTPS and transfer checks separately. Inspect certificate/time errors, profile details, system logs, and fallback behavior. A process being alive or one HTTP response succeeding is weaker evidence than a successful application transfer.

## A domain has no current IPs

Check the saved group or provider rule, then resolve the domain from the affected device. Check the configured DNS path in YAML, resolver availability, and DNS errors or fallback events in the local journals. Provider rules learn addresses from DNS answers seen by KeenProxy and keep them for the answer's TTL. [Provider rules](routing.md#provider-rules) · [Inspect local journals](#inspect-local-journals)

## Why does the watchdog restore interception rules?

Older Keenetic Entware builds (such as `iptables 1.4.21-6`) can accept `-w` in `iptables` but reject it in `iptables-restore`. KeenProxy retries once without `-w` only for the known glibc (`invalid option -- 'w'`) or musl (`unrecognized option: w`) diagnostic. It keeps `--noflush` to preserve unrelated firewall rules. Other restore errors are reported as-is. This does not bypass missing Netfilter or TPROXY support.

The watchdog checks the required firewall entry jumps every 30 seconds by default. A failed check triggers a repair attempt. The audit event records the first failed table, built-in chain, target, exit code and command error. Exit code 1 is reported as a failed check, because the code alone cannot establish why the command failed. A value of -1 means no normal process exit code was available.

On a managed Linux installation, KeenProxy also enables an optional NDM callback when `/var/run/ndm.core.socket` and `/opt/etc/ndm` are present. This covers compatible Keenetic/Netcraze firmware without assuming every router supports NDM. The daemon owns `/opt/etc/ndm/netfilter.d/99-keenproxy.sh` and a private runtime event file. IPv4 `nat`, `filter` and `mangle` callbacks request a serialized check of the current rules without restarting the engine. Repeated notifications coalesce. The 30-second watchdog remains active on every platform, including when callback setup fails.

A clean exit removes the managed hook. Uninstall also cleans up the managed hook after the service has stopped, including leftovers from an interrupted shutdown. Foreign hook files are preserved. A callback queued after shutdown or binary rollback exits harmlessly when the event file is absent. The system journal records `netfilter event hook enabled` at startup. The repair count appears under **Diagnostics → State → Firewall watchdog**. Each repair attempt appears once in the audit journal, with exit codes, raw command errors, and its trigger when recorded. The recorded duration measures the work from the first check through verification. Packet loss can still occur while callbacks run and rules are applied. The system journal retains hook setup/watcher errors and failed recovery. [Inspect local journals](#inspect-local-journals) · [NDM hook contract](https://support.keenetic.ua/titan/kn-1811/en/42407-opkg-component-description.html)

After applying the rules, the watchdog checks the entry jumps again. If verification fails, it waits briefly and retries the repair once to allow for firmware replacing several tables in succession. The counter increases only after verified recovery, including retries of failed rule updates; it does not count firmware rebuilds specifically. A failure records the initial check, the final attempt's outcome, and its verification result if verification ran. If both a configuration apply and its rollback fail while installing firewall rules, the watchdog can retry the pending plan once its engine, DNS listener, and policy routing are ready. After a failed rollback, KeenProxy attempts to block public forwarding and direct DNS for the previously protected sources until interception recovers. Failed rule updates after device address changes are also retried, even when the old entry jumps still exist. If rollback fails earlier while preparing dependencies, firewall recovery cannot safely restore the configuration: resolve the reported engine, DNS, or routing error, then apply the configuration again or restart the service. A successful check establishes entry-jump presence at that moment. It does not validate every rule inside the chains, TPROXY policy routes, or end-to-end connectivity.

During recovery from a failed rollback, the watchdog replaces the temporary drop rules only after it installs and verifies the required firewall entry jumps.

For repeated recoveries, record the times of the triggering actions and export the diagnostics ZIP together with the router system log. The ZIP retains structured firewall evidence under the audit entry's `firewall` field, including the optional `trigger` (`netfilter_hook` or `watchdog`) and nonnegative `duration_ms`, any failed `before` and `after` checks, and `outcome` (`restored`, `apply_failed`, or `verify_failed`). Raw command errors remain in the local journals. The ZIP keeps only known rule identities, exit codes, reasons and coarse error categories. Older entries have no `firewall` field.

## TPROXY fails or blocks startup on Keenetic { #keenetic-tproxy-apply }

The error `iptables-restore: line N failed` can have several causes. Start with the exact error and the `firewall_apply.restore` entry. If the reported operation is `commit`, it identifies the table whose commit failed. [Diagnostic ZIP](#download-the-diagnostic-zip)

### Retry blocked startup over SSH { #retry-blocked-tproxy-startup }

If the saved TPROXY settings block startup, the panel stays accessible while
interception is stopped. From an Entware SSH session on the router, check the
preliminary readiness and startup state. The control API must accept loopback
connections. These examples use `127.0.0.1:8086`. Substitute the loopback
address and port accepted by your `api.listen` if they differ.

```sh
curl -sS -i http://127.0.0.1:8086/api/diagnostics/tproxy
```

An HTTP `200` response with `"startup_blocked": true` confirms that startup is
blocked. An `unknown` readiness result allows KeenProxy to attempt activation.
On OpenWrt with `iptables-nft`, the legacy iptables target list may be incomplete.
Use the kernel checks below to fix the reported cause, then retry the saved
settings. The retry preserves the configuration file and its backup.

```sh
curl -sS -i -X POST http://127.0.0.1:8086/api/diagnostics/tproxy/retry
```

Read the HTTP status line and the JSON body. After HTTP `200`, repeat the GET
and confirm that `"startup_blocked": true` is gone. HTTP `409` means there is
no blocked startup to retry. If the retry returns HTTP `422`, read the JSON
`error` field for the failure reason.

If `api.listen` binds only to the router's LAN address, use the Entware
service controller after fixing the cause. Restarting starts KeenProxy with
its saved settings and the configured bind.

```sh
/opt/etc/init.d/S99keenproxy restart
```

In the KeeneticOS component list, check **Open Package support (OPKG)** and **Kernel modules for Netfilter**. Entware supplies the `iptables` commands separately. Even with Netfilter and Xtables-addons installed, the TPROXY module may be present on disk but not loaded.

**Kernel and iptables checks.** Save as `test1.sh` and run `sh test1.sh` in an Entware SSH session. This does not apply rules or explicitly load modules.

```sh
#!/bin/sh
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
section() { printf '\n=== %s ===\n' "$1"; }
iptables=/opt/sbin/iptables
restore=/opt/sbin/iptables-restore

section 'Kernel and Entware'
uname -rm
if command -v opkg >/dev/null 2>&1; then
    opkg list-installed | grep -E '^(iptables|xtables)([[:space:]]|-)'
else
    echo 'opkg not found'
fi

section 'iptables and iptables-restore'
ls -l "$iptables" "$restore"
"$iptables" -w --version 2>&1
printf 'iptables version exit=%s\n' "$?"
"$restore" --help </dev/null 2>&1

section 'Kernel targets and modules (before iptables probes)'
if [ -r /proc/net/ip_tables_targets ]; then
    if grep -qx TPROXY /proc/net/ip_tables_targets; then
        echo 'TPROXY target: registered'
    else
        echo 'TPROXY target: not listed or unreadable'
    fi
else
    echo '/proc/net/ip_tables_targets unavailable'
fi
if [ -r /proc/modules ]; then
    awk '
        $1 ~ /^(xt_TPROXY|xt_socket|iptable_mangle)$/ {
            printf "%s: loaded (size=%s, refs=%s)\n", $1, $2, $3
            found = 1
        }
        END { if (!found) print "No matching loadable modules listed" }
    ' /proc/modules
else
    echo '/proc/modules unavailable'
fi

section 'TPROXY userspace extension'
help=$("$iptables" -t mangle -j TPROXY --help 2>&1)
if ! printf '%s\n' "$help" |
    grep -Ei 'TPROXY target options|--on-port|--on-ip|--tproxy-mark|error|failed|not found'; then
    printf '%s\n' "$help" | tail -10
fi

section 'IPv4 mangle and KeenProxy rules'
"$iptables" -w -t mangle -S >/dev/null
printf 'mangle read exit=%s\n' "$?"
if rules=$("$iptables" -w -t mangle -S KEENPROXY_UDP 2>&1); then
    printf '%s\n' "$rules" | awk '
        / -j TPROXY( |$)/ { count++ }
        END { printf "KEENPROXY_UDP: %d TPROXY rule(s)\n", count }
    '
else
    printf 'KEENPROXY_UDP unavailable: %s\n' "$rules"
fi

section 'Recent kernel messages'
if messages=$(dmesg 2>&1); then
    matches=$(printf '%s\n' "$messages" |
        grep -Ei 'tproxy|x_tables|ip_tables|unknown symbol|invalid module' |
        tail -30)
    printf '%s\n' "${matches:-No matching kernel messages}"
else
    printf 'dmesg unavailable: %s\n' "$messages"
fi
```

**Module files and tools.** Save as `test2.sh` and run `sh test2.sh` to check the running firmware without loading anything. An unavailable `/proc/config.gz` does not prevent the other checks.

```sh
#!/bin/sh
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
section() { printf '\n=== %s ===\n' "$1"; }
release=$(uname -r)
module="/lib/modules/$release/xt_TPROXY.ko"

section 'Module for the running kernel'
printf 'Kernel release: %s\n' "$release"
if [ -f "$module" ]; then
    ls -l "$module"
else
    printf 'Not found at the expected path: %s\n' "$module"
fi

section 'Other TPROXY module files'
for dir in /lib/modules /opt/lib/modules; do
    printf '%s:\n' "$dir"
    if [ -d "$dir" ]; then
        matches=$(find "$dir" -type f -iname '*tproxy*.ko*' -print)
        printf '%s\n' "${matches:-  No matching files}"
    else
        echo '  Directory unavailable'
    fi
done

section 'Module tools (not executed)'
for tool in modprobe insmod modinfo; do
    if path=$(command -v "$tool"); then
        printf '%s: %s\n' "$tool" "$path"
    else
        printf '%s: not found\n' "$tool"
    fi
done

section 'Kernel build options'
if [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
    zcat /proc/config.gz |
        grep -E '^(# )?CONFIG_(NETFILTER_XT_TARGET_TPROXY|NF_TPROXY_IPV4)(=| is not set)' ||
        echo 'No matching options found or kernel config could not be read'
else
    echo '/proc/config.gz or zcat unavailable'
fi
```

If the help lists `--on-port`, `--on-ip`, and `--tproxy-mark`, the Entware command recognizes the extension. A successful `mangle` read only confirms that the table is accessible. Neither proves that the kernel will accept a TPROXY rule. `TPROXY` in `/proc/net/ip_tables_targets` confirms that the target is registered; absence from `/proc/modules` alone does not rule out built-in support.

**If the target is missing but the firmware module exists**, the router owner can try loading it temporarily. Keep local recovery access and do this when it is safe to retry interception. Use the module shipped with the running firmware.

Save the optional loader as `load-tproxy.sh` and run it separately with `sh load-tproxy.sh`. It skips `insmod` if the target is already registered, the module is already loaded, or either kernel check fails.

```sh
#!/bin/sh
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin

targets=/proc/net/ip_tables_targets
modules=/proc/modules
module="/lib/modules/$(uname -r)/xt_TPROXY.ko"

if grep -xq TPROXY "$targets"; then
    echo 'TPROXY target already registered; skipping insmod'
    exit 0
elif [ "$?" -ne 1 ]; then
    echo 'Cannot check kernel targets; skipping insmod' >&2
    exit 1
fi
if grep -q '^xt_TPROXY ' "$modules"; then
    echo 'xt_TPROXY already loaded but target not listed; skipping insmod' >&2
    exit 1
elif [ "$?" -ne 1 ]; then
    echo 'Cannot check loaded modules; skipping insmod' >&2
    exit 1
fi
if [ ! -f "$module" ]; then
    printf 'Firmware module not found: %s\n' "$module" >&2
    exit 1
fi
insmod "$module" || exit "$?"
grep -x TPROXY "$targets"
```

The target appeared after this step in the reported case. [Issue #39](https://github.com/ordo-systems/keen-proxy/issues/39)

If the target appears on your router and startup was blocked, retry the saved
settings over SSH. The procedure covers loopback API access and a LAN-only
listener. [Retry blocked startup over SSH](#retry-blocked-tproxy-startup)

After activation, check that `/opt/sbin/iptables -w -t mangle -S KEENPROXY_UDP`
shows a `-j TPROXY` rule for participating clients. Then test UDP traffic from
one of them. Manual module loading lasts until reboot. If loading fails, save
the error and the relevant lines from `dmesg | tail -30`. If activation still
fails, include the full error and the reviewed diagnostic ZIP. If you can
work without transparent UDP interception, set `mode: redirect` under
`intercept:` in YAML while investigating. Redact private addresses and kernel pointers before
sharing command output.

## Download the diagnostic ZIP

1. Reproduce the problem and note the approximate time and time zone. Open **Diagnostics** in the web panel on your router.
2. With a management account, choose **Download ZIP** under **Support report**. Review the contents of the downloaded `keenproxy-diagnostics-*.zip` before sharing.

| File | What it contains |
| --- | --- |
| `README.txt` | Archive format and a summary of the privacy rules |
| `config.json` | A sanitized summary of applied settings, including routing, connections, and DNS policies |
| `status.json` | Runtime state at export time, including build identity, interception, connection health, and active fallbacks |
| `journals/routes.jsonl`, `journals/audit.jsonl`, `journals/system.jsonl` | All readable records still retained by KeenProxy, with one event per line |

The ZIP includes the applied settings and records still retained in memory and on disk. Older records may have rotated out.

When `iptables-restore` fails during Apply, look for **Configuration apply failed** in `journals/audit.jsonl`. `firewall_apply.restore` describes the failed attempt; `rollback_restore` describes a separate restore failure during rollback, if any. The ZIP records the exit code, whether `-w` was used, and, when reported, the input line number and known table, operation, chain, and jump target. A `commit` failure identifies a table, not a particular rule. Watchdog failures use `firewall.restore`. Raw errors remain in the local journal; the ZIP does not include rule arguments or raw stderr.

The export omits credentials, raw connection profiles, and free-form log messages. Names and addresses are removed or replaced with aliases that are consistent within one ZIP. Event times, ports, protocols, policies, and counts can still identify activity. Review the files before attaching them to an issue or sharing them privately.

For a restorable configuration, copy the YAML configuration file over SSH and store it privately.

## Inspect local journals { #inspect-local-journals }

Run these read-only requests from an SSH shell on the router. Use the configured API port if it differs from 8086.

```sh
curl -fsS 'http://127.0.0.1:8086/api/journal/routes?limit=20'
curl -fsS 'http://127.0.0.1:8086/api/journal/audit?target=firewall&limit=20'
curl -fsS 'http://127.0.0.1:8086/api/journal/system?limit=20'
```

Match a recent route to the affected device and destination, then compare its `rule` and `outbound` with the configured policy. An audit request can use `target=dns` to check DNS fallback. Keep local journal output private and share the ZIP from **Diagnostics → Support report → Download ZIP** for support. [Loopback control API](development.md#control-api)

## What should a bug report include?

Include the expected and actual behavior, the running release and build details, router model and firmware, steps to reproduce, and the approximate time of the incident. Use a minimal synthetic configuration or attach a reviewed [diagnostic ZIP](#download-the-diagnostic-zip). Read [CONTRIBUTING](https://github.com/ordo-systems/keen-proxy/blob/main/CONTRIBUTING.md) and [SECURITY](https://github.com/ordo-systems/keen-proxy/blob/main/SECURITY.md).

## Recover panel access { #recover-access }

Requests from the router itself are always trusted: a request from `127.0.0.1` that also addresses `127.0.0.1` or `localhost` skips sign-in. When KeeneticOS sign-in does not work (unknown firmware, a changed RCI, no LAN address at startup, or sign-in turned off), open the panel through an SSH tunnel. On Keenetic, connect to the Entware SSH server on port 222; port 22 is the KeeneticOS command line:

```sh
ssh -p 222 -L 8086:127.0.0.1:8086 root@ROUTER
```

Then open `http://127.0.0.1:8086` and keep that address: the panel trusts the tunnel only while the browser addresses `127.0.0.1` or `localhost`. On OpenWrt, use the default SSH port: `ssh -L 8086:127.0.0.1:8086 root@ROUTER`. The control API under `/api` answers only such loopback requests; a KeeneticOS session never reaches it.

If browsers on the LAN get `503` and the system journal reports that KeeneticOS sign-in is unavailable, fix the reported cause (the LAN address, `api.listen` or the origin) and restart the service. The derived origin expects the router's web interface on port 80 at the LAN address; if it uses another port, set `KEENPROXY_KEENETIC_AUTH_ORIGIN=http://ROUTER_LAN_IP:PORT`. To keep sign-in off, set `KEENPROXY_KEENETIC_AUTH_ORIGIN=off`; the panel then opens only through the tunnel. On Entware, put the line in `/opt/etc/keenproxy/keenproxy.env`, which updates and uninstall keep (only `KEENPROXY_NAME=value` lines are read; nothing is executed), and run `/opt/etc/init.d/S99keenproxy restart`. See [KeeneticOS sign-in](development.md#keenetic-auth).

## Upgrading from v0.10 { #upgrade-from-v010 }

This release no longer reads every v0.10 configuration. A file that still loads is used as is. A file that does not load is reset in memory at startup: the listen address, LAN settings and the first valid subscription are kept, and the file itself stays unchanged. When the LAN interface has a private IPv4 address, the reset routes that home LAN through the kept subscription using its provider rules; without one, nothing is routed until you add a network. Either way, the first save keeps the original byte for byte as `config.v1.yaml` next to the configuration before it writes the new format, so rolling back before that save leaves the older release its own file. A file that holds only installer starter settings is not kept. Re-create other connections and rules afterwards. Presets, resource exchange, ad filter lists and YAML import/export no longer exist, and there is no panel token to look up. A fresh install has no v1 backup, so a [rollback](getting-started.md#update-from-the-panel) to an older release is refused and changes nothing.
