# Getting started

The bootstrap installs the LokiVPN release for your router and checks each downloaded file against the release manifest. Use the GitHub source build instructions to build the `master` branch. [LokiVPN releases](https://github.com/LokiVPN/keen-proxy/releases) · [Source build](https://github.com/LokiVPN/keen-proxy#build-and-try-the-interface)

## Experimental OpenWrt support

KeenProxy requires **at least 256 MiB of total RAM** on OpenWrt and Keenetic/Netcraze routers, plus enough storage for the binary and its data. Releases provide full and lite Linux binaries for x86-64 (`amd64`, baseline v1), 32-bit x86 (`386`, requires SSE2), ARM32 (ARMv5 or later, soft float, suffix `armv5`), ARM64 (`arm64`), little-endian MIPS (`mipsle`, soft float), and big-endian MIPS (`mipsbe`, soft float).

Native OpenWrt installation and panel updates use the system shell and procd, without Entware. Both native OpenWrt and Entware support the six release architectures listed above. The interception runtime still requires compatible `iptables`, `iptables-restore`, and kernel support. Verify interception with a test client on your firmware, especially on systems using firewall4. This does not add a native nftables backend. [OpenWrt netfilter documentation](https://openwrt.org/docs/guide-user/firewall/netfilter_iptables/netfilter_management)

The optional NDM netfilter hook is specific to compatible Keenetic/Netcraze firmware. On OpenWrt without NDM it stays disabled and creates no NDM hook or event files; the regular watchdog continues checking every 30 seconds by default. No OpenWrt hotplug or firewall4 integration is installed. See [firewall recovery](network-flow.md#how-firewall-rules-recover-after-a-firmware-change).

### Native OpenWrt installation

Keep SSH/LAN recovery access, back up the configuration, and stop competing DNS/traffic interceptors. As soon as a network or device policy includes devices, the service intercepts their DNS. Ensure enough persistent overlay storage for the binary, a staged replacement, and a rollback copy; `/tmp` free space alone is not sufficient.

Install `curl`, CA certificates, and compatible iptables tools using the package manager for your firmware (`opkg` or `apk`). Package names vary by release; common choices include `curl`, `ca-bundle`, and `iptables-nft`. REDIRECT needs NAT support; UDP TPROXY additionally needs matching TPROXY/mangle modules. Installing a package does not prove its compatibility with your firmware.

Check the native environment before installation:

```sh
uname -m
df -h /overlay /usr
free
test -x /sbin/procd && test -f /etc/openwrt_release
test -x /usr/sbin/iptables-restore
/usr/sbin/iptables -t nat -S
```

Then run as root:

```sh
curl -fsSL https://raw.githubusercontent.com/LokiVPN/keen-proxy/master/tools/bootstrap.sh | KEENPROXY_PLATFORM=openwrt /bin/sh
```

The bootstrap installs `/usr/bin/keenproxy`, enables `/etc/init.d/keenproxy` for boot through procd, and starts the service. It verifies checksums and validates the configuration before replacing a running version. A failed startup triggers restoration of the previous files and service. Full and lite builds both embed TrustTunnel; no external helper is needed.

The clean configuration is `/etc/keenproxy/config.yaml`, with `lan.interface: br-lan`. Change the bridge name if your firmware differs. Existing configurations are preserved. The CLI retains Entware defaults, so pass the native configuration explicitly:

```sh
keenproxy --url -config /etc/keenproxy/config.yaml
/etc/init.d/keenproxy status
```

Use the same bootstrap command to update. Append `-s -- --version vX.Y.Z --lite` to `/bin/sh` to choose a release/variant; append `-s -- --uninstall` to stop and disable the native service and remove its binary/init script while retaining settings. Panel updates and scheduling work as described below.

OpenWrt uses [SSH tunnel access](user-guide.md#ssh-tunnel) for the management pages. Once the tunnel is open, follow [First configuration](#first-configuration).

Native release transactions require the checksummed `keenproxy.openwrt` asset. Older releases without it are not valid native installation or rollback targets; rejection leaves the running version unchanged. Release records and update preferences live persistently under `/usr/share/keenproxy/`; rule sets, logs, and derived state under `/var/lib/keenproxy/` are normally volatile on OpenWrt.

Automatic detection preserves an existing managed Entware installation rather than migrating it on an OpenWrt host. `KEENPROXY_PLATFORM=openwrt` explicitly selects native installation; do not run native and Entware instances simultaneously. The remaining router-preparation and Entware shell commands below describe the Entware path only.

## Prepare the router

### Hardware and firmware

- **CPU.** The installer supports the six release architectures listed above. Use a matching Linux userspace; 32-bit x86 requires SSE2. For MIPS, confirm the byte order with the package architecture or the model guide.
- **Firmware.** Use a Keenetic or Netcraze model with Open Package support (OPKG), an Entware shell, and compatible `iptables` tools. TCP interception uses REDIRECT. UDP interception in `tproxy` mode also requires kernel TPROXY support and policy routing.
- **Storage.** Use an external USB drive for Entware and KeenProxy. Compare the release binary size with the free space on `/opt` and leave room for Entware, the configuration, rule sets and filter data, and a rollback copy. The lite binary is smaller and supports fewer protocols.
- **RAM.** At least **256 MiB of total router RAM**, including for lite builds. This is the supported hardware floor, not a guarantee that every workload fits. Check available memory with your usual router services running; reserve headroom for firmware, the engine, connections, and enabled lists. Monitor memory during the first test with your own configuration. The default 768 MiB Go memory recommendation is not a physical-memory requirement or a hard RSS limit.

**Recommended firmware component.** Enable **Kernel modules for Netfilter** alongside OPKG if your model offers it. It supplies kernel support for packet filtering used by `iptables`; the Entware commands are a separate prerequisite. Check the component list for your exact model. [KeeneticOS component reference](https://support.keenetic.com/hopper/kn-3810/en/16327-os-component-description.html)

If Apply fails with UDP interception enabled, see [TPROXY troubleshooting on Keenetic](troubleshooting.md#keenetic-tproxy-apply).

### Choose where to install Entware

| Method | How it works |
| --- | --- |
| **USB drive (recommended)** | A standard USB flash drive that your router recognizes is sufficient if it has enough space. Prepare an ext4 partition as described below, enable OPKG, then place the installer archive for your model in the partition's `install` folder. Select that partition in OPKG Package Manager. [Keenetic USB guide](https://support.keenetic.com/hopper-se/kn-3812/en/20980-installing-the-entware-repository-on-a-usb-drive.html) |
| **Internal storage (not recommended)** | Available on selected models and firmware versions. The built-in partition can leave little room for updates and a rollback copy. If you use it, check free space on `/opt` before installing KeenProxy. The vendor guide covers setup from OPKG Package Manager, the CLI, and an installer archive. [Keenetic internal storage guide](https://support.keenetic.com/titan/kn-1811/en/18482-installing-opkg-entware-in-the-router-s-internal-memory.html) |

**Prepare the USB drive on the router.** On supported models running KeeneticOS or NetcrazeOS 5.1 or later, enable the **Ext filesystem** component and the **EXT4 filesystem utilities** in the firmware component settings. Connect the drive and open **Management → Storage & Devices**. Choose **Format** for the partition you want to use, then select **EXT4**. Formatting erases the selected partition, so back up its files first. If the router does not offer this feature, format the drive as ext4 on a computer. [Keenetic formatting guide](https://support.keenetic.com/hero/kn-1013/en/100924-formatting-and-checking-a-file-system-on-a-usb-drive.html)

The linked manuals use specific models as examples. Use the components and installer archive listed for your own model.

### Verify the environment

After Entware setup, connect to the Entware shell from the LAN and change its initial password. Back up the router settings and keep local access for recovery. Run these read-only checks before copying KeenProxy:

```sh
uname -m
opkg print-architecture
df -h /opt
free
command -v iptables
command -v iptables-restore
iptables -t nat -S
```

Confirm the architecture, free disk space, available memory, and firewall tools. Start with an example configuration and replace its placeholder connection details privately.

The last command lists IPv4 NAT rules without editing them. For `tproxy` mode, also check that `iptables -t mangle -S` succeeds. Table access is a preliminary check. Verify REDIRECT or TPROXY with traffic from a test client before relying on interception.

## Install or update from GitHub

Install `curl` and the CA certificates in the Entware root shell if needed.

```sh
opkg update && opkg install curl ca-bundle ca-certificates
```

Stop competing traffic or DNS interception services before installation. KeenProxy intercepts DNS only for devices that a network or device policy includes; the starter configuration has none, so nothing is intercepted until you add one. Run the bootstrap once a LokiVPN release is available. [Releases](https://github.com/LokiVPN/keen-proxy/releases)

```sh
curl -fsSL https://raw.githubusercontent.com/LokiVPN/keen-proxy/master/tools/bootstrap.sh | /opt/bin/sh
```

The installer reads `BUILD_INFO.txt` from the latest published LokiVPN release, detects the CPU, and verifies the release files against `SHA256SUMS`. It installs missing Entware `iptables` tools, creates a starter configuration if needed, and registers and starts `S99keenproxy` through the Entware init mechanism. TrustTunnel runs inside sing-box-lx; no separate client is installed. After installation and command-line updates, it prints the panel URL when the installed binary can determine it. See [panel access](user-guide.md#access-the-panel).

On a clean install, the bootstrap creates a starter `/opt/etc/keenproxy/config.yaml`. KeenProxy fills in defaults when it loads the file and writes new configurations with `schema_version: 2`. Use [First configuration](#first-configuration) to sign in and enable routing.

Run the same command to update. A configuration this release cannot load is reset in memory when the service starts; the kept subscription then routes the home LAN with its provider rules. The file itself changes only at the first save, which keeps the original as `config.v1.yaml` (unless it holds only installer starter settings), so an older release can still read it if the update is rolled back before then. See [configuration schema 2 and rollback](development.md#config-schema). This release's installer also snapshots the configuration before installing and restores it if the update fails. The installer stages and validates the candidate before stopping the managed service. If the new service fails its startup check, it attempts to restore the previous files and restart the previous service. A manually started instance must be stopped before the installer can take over.

To choose a release, replace `vX.Y.Z` with a published tag. The optional `--lite` flag selects the smaller build without QUIC/HTTP/3. `--without-trusttunnel` remains accepted for existing updaters and scripts, but no longer changes the payload: TrustTunnel is embedded. `--trusttunnel-only` is no longer accepted.

```sh
curl -fsSL https://raw.githubusercontent.com/LokiVPN/keen-proxy/master/tools/bootstrap.sh | /opt/bin/sh -s -- --version vX.Y.Z
```

The tag must have installer assets and checksums attached. If publication is still in progress, wait for the assets and rerun the command. Service commands are `status`, `start`, `stop`, and `restart` on `/opt/etc/init.d/S99keenproxy`. See the root README for manual installation. [Installation reference](https://github.com/LokiVPN/keen-proxy#configuration-and-router-installation)

On Entware, the service tries to raise the daemon's open-file limit to at least 8192 at startup, keeping any higher limits. If the system does not allow the increase, the service warns and still starts. To confirm the effective limit, check `Max open files` in `/proc/<PID>/limits` for the KeenProxy process.

## Update from the panel

On a managed Entware or native OpenWrt installation, **Diagnostics → Updates** shows the installed version, the latest available stable release, and the previous installed version when recorded. Upgrade once with the command-line bootstrap if the current build predates panel updates. To make that older release a rollback target, first rerun the current bootstrap with the exact tag and build variant already installed, then upgrade. Native OpenWrt additionally requires that target release's procd asset.

Update actions and schedule changes require [management access](user-guide.md#access-the-panel). OpenWrt installations use the [SSH tunnel](user-guide.md#ssh-tunnel).

Automatic installation is off by default. The panel still checks for releases. Enable automatic installation and save a time to install available releases during that minute in the router's local time, once per day while the service is running. Installation briefly restarts KeenProxy.

To move an Ordo Systems installation to LokiVPN, turn off automatic installation and save the current binary and configuration privately. Run the LokiVPN bootstrap over SSH with `--version vX.Y.Z`, using a published LokiVPN tag, and add `--lite` for an existing lite install. Subsequent panel updates use the LokiVPN release channel. Keep the matching configuration and upstream package for a rollback across release channels.

The protected installer blocks forwarded traffic before stopping the old service. The router remains reachable from the LAN. Forwarding resumes once interception is active in the new release or in the restored release after a failed update. If neither restores interception, forwarding stays blocked. From the LAN, rerun the bootstrap with a working release and configuration to restore access. If IPv6 forwarding is enabled, the installer also needs working `ip6tables`. On OpenWrt, disable software and hardware flow offloading and reload the firewall before updating. The guard covers traffic that passes through the router's Netfilter forwarding chains.

On KeeneticOS with IPv6 forwarding, the updater needs the Netfilter `comment` match for its temporary forwarding rule. If `ip6tables` reports `No chain/target/match by that name`, check that `ip6tables -t filter -S FORWARD` succeeds and look for `comment` in `/proc/net/ip6_tables_matches`. If the match is absent, load the module supplied by the running firmware from the Entware root shell.

```sh
module="/lib/modules/$(uname -r)/xt_comment.ko"
test -r "$module" && insmod "$module"
grep -Fx comment /proc/net/ip6_tables_matches
```

Rerun the bootstrap once the match is listed. Check for it again after a router reboot.

If the service starts in `management-only` mode, the panel can open while traffic interception is unavailable. When TPROXY blocks startup, check readiness and retry the saved configuration from the router shell. If the protected bootstrap left a forwarding guard, rerun it with a working release and configuration to remove the guard. [Retry blocked TPROXY startup](troubleshooting.md#retry-blocked-tproxy-startup)

**Roll back** reinstalls the previous published version and switches off automatic installation. It needs access to GitHub and keeps the existing configuration. The installer rejects an incompatible configuration before restarting the service. A schema 2 file is not readable by older releases: the rollback switches to the newest kept `config.v1*.yaml` and keeps the newer file as `config.v2*.yaml`. A fresh install of this release has no v1 backup, so rolling back to an older release is refused and changes nothing. Use the command-line installer to upgrade again. See [upgrading from v0.10](troubleshooting.md#upgrade-from-v010).

## First configuration { #first-configuration }

1. On KeeneticOS, sign in to the router with a management account. Open **Management → Applications → KeenProxy** or use the address printed by the installer. On OpenWrt, open the browser at `http://127.0.0.1:8086` while the SSH tunnel is running. [Panel access and roles](user-guide.md#access-the-panel)
2. Paste your LokiVPN subscription link, choose **Check**, then **Enable** to apply the detected home-network policy. A device-limit or expiry message links you to the account when the provider supplies an account page. [First run and manual setup](user-guide.md#first-run)
3. Use **Overview** to confirm the main connection. Use **Routing** for rules and **Devices** for device access. **Connections** shows the subscription nodes and manual profiles. **Diagnostics** shows service readiness and provides checks, support reports, and updates. [Management pages](user-guide.md#overview)
4. Test the intended traffic from a participating device and use **Diagnostics** if results differ from what you expect. A successful HTTP check covers that request. Check HTTPS and DNS separately if they are part of the issue.

## Recover access { #recover-panel-access }

If the KeeneticOS session check fails, open the panel through an SSH tunnel to the router's loopback listener. Use the Entware SSH server on KeeneticOS and the system SSH server on OpenWrt. [SSH command and browser address](user-guide.md#ssh-tunnel)

Keep a private configuration backup and access to your previous release before upgrading. [Installation and rollback](#update-from-the-panel) · [Sign-in troubleshooting](troubleshooting.md#recover-access)

## Uninstall

Run from the Entware root shell:

```sh
curl -fsSL https://raw.githubusercontent.com/LokiVPN/keen-proxy/master/tools/bootstrap.sh | /opt/bin/sh -s -- --uninstall
```

The command stops the managed service and removes `/opt/bin/keenproxy` and `/opt/etc/init.d/S99keenproxy`. It preserves `/opt/etc/keenproxy/` (including configuration), `/opt/var/lib/keenproxy/` (logs and derived state), and any previously installed external TrustTunnel client. KeenProxy no longer uses that executable. Run the regular installer again to reuse your settings.
