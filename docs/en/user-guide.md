# User guide

## Access the panel { #access-the-panel }

1. From your local network, sign in to the KeeneticOS web interface in the browser you will use for KeenProxy.
2. Open **Management → Applications** and choose **Open panel** on the KeenProxy card. If the card is unavailable, use the address printed by the installer. You can get it again with `keenproxy --url`. The default panel port is `8086`.
3. Keep the same hostname as your KeeneticOS session. If you signed in by the router's LAN address, open KeenProxy at `http://ROUTER_LAN_IP:8086`. If you used `my.keenetic.net`, use the card or `http://my.keenetic.net:8086`.

| Router account | Access |
| --- | --- |
| Administrator with web and CLI access | Manage settings, run checks, download support reports and control updates. |
| Read-only or manager account with web access | View pages and status. Settings and management actions are disabled, and connection credentials stay hidden. |
| Other accounts | KeenProxy shows **Access denied**. |

If your session expires, follow **Sign in to KeeneticOS** and reopen KeenProxy. **Sign out** ends the router session. KeenProxy follows your browser's preferred language (Russian or English) and your system's light or dark preference. On phones, swipe the tab bar sideways to see all five tabs.

If the sign-in check is unavailable or your installation runs on OpenWrt, use [SSH tunnel access](#ssh-tunnel).

<a name="first-run"></a>

## First run { #first-run }

1. Open KeenProxy with a management account. On a fresh setup it asks for a subscription link.
2. Paste the HTTPS link from your LokiVPN account and choose **Check**. This may use one device slot. Review the server list and any expiry, usage, rules, or provider message returned. If the device limit is reached, remove an unused device in your account. If the subscription has expired, renew it. Check the link again after either change.
3. Choose **Enable** to save the subscription and apply split routing to the detected home network. KeenProxy uses the provider profile when available. Without one, unmatched traffic uses the subscription. This setup requires a private IPv4 address on the configured LAN interface.
4. Open **Overview** to confirm the selected connection and **Devices** to choose which devices use it. Test an intended site from one of those devices.

To add a subscription to an existing setup, choose **Overview → Set up subscription**, check the link, then choose **Add subscription**. To update the current link, choose **Overview → Replace link**, check the replacement, and confirm **Replace link**. The replacement keeps the subscription identifier, reserve, and existing routing and device settings.

For a manual setup, open [Connections](#connections). From the initial setup screen, you can reach it by appending `/connections` to the panel address. Add a connection there. If the home network has no policy yet, configure it in [YAML](#configuration-and-backups). Then select the connection on **Overview**.

<a name="overview"></a>

## Overview { #overview }

- **Enabled** pauses or resumes routing for the whole network. While paused, devices use their regular internet path. **Main connection** selects an automatic or balanced subscription target, a specific node, or a manual connection. Both controls apply immediately. With JavaScript disabled, use the accompanying **Save** button.
- The status names the active connection or reserve and shows when a path is unavailable. **Subscription** shows the provider's expiry and usage, when supplied, and the last and next refresh. **Update now** queues a refresh for the subscription shown here.
- **VPN traffic** covers the last 30 minutes. Raw groups that can use both direct and VPN members may include direct traffic in the chart. The device and routing summaries link to their tabs.

<a name="routing"></a>

## Routing { #routing }

Choose a mode and select **Save**.

- **By subscription rules** follows the provider's rules and default route. Review the **Through VPN**, **Direct**, and **Block** sections. Switch off individual rules as needed. A disabled rule stays off after the subscription refreshes. Rules that are loading, missing, or unavailable have an explanation.
- **All traffic through VPN** uses the main connection for traffic beyond the home network, subject to your exceptions.
- **Only my sites** sends the listed sites through the main connection and sends unmatched traffic directly.

In **My sites**, enter one domain, IP address, or subnet per line. Domains include their subdomains. Use the direct list for exceptions and keep each entry in just one list. Advanced routing groups and DNS settings are managed in YAML. [Routing and DNS](routing.md)

<a name="devices"></a>

## Devices { #devices }

KeenProxy shows devices discovered on the LAN and configured devices, including saved devices that are offline. Switch VPN routing on or off for individual devices, or choose **Enable for all** or **Disable for all**. Review any notice beside a device that has no applicable VPN route.

**New devices use the VPN right away** sets the default for new home-network devices. The switches displayed for existing devices keep their setting when you change this default. Choose **Save** to apply the list and default. **Cancel** returns to the saved settings.

<a name="connections"></a>

## Connections { #connections }

### Native subscriptions { #native-subscriptions }

The subscription section shows nodes, their most recent HTTPS check, and any rule notices. Use **Update now** for that subscription, **Check** for one node, or **Check all nodes** for the catalog. The checks verify the server certificate. These actions keep staged changes on the form. Select **Save** to apply a reserve or a manual connection switch.

In **Reserve if none of the nodes respond**, choose a manual connection, **Direct — without VPN**, or **None — block VPN traffic**. When a manual reserve is down or disabled, its own configured reserve chain decides where traffic goes. **No reserve configured** preserves an unset reserve. [Subscription reserves](routing.md#subscription-reserve)

Under **Main connection** on **Overview**, **Auto — switch nodes on failure** follows the provider order and stays with a working node after failover. **Current** indicates the selected node and can appear alongside **Unavailable** after a failed check. A pinned node remains selected and uses its configured reserve if the node disappears. **Balancing by rotation**, **by site**, and **by session** distribute new connections across eligible nodes. [Selection and balancing](routing.md#subscription-reserve)

KeenProxy accepts HTTPS Xray share lists in plain text or Base64, up to 2 MiB and 256 distinct nodes. If a refresh fails, it retains the last validated list and shows the refresh status. Keep subscription links private.

### Add or replace a manual connection { #manual-connections }

1. Choose **Add connection**. Use **Paste** for a share link, standalone Amnezia `vpn://` client export, WireGuard or AmneziaWG `.conf` text, or one sing-box outbound or endpoint in JSON. **From file** accepts these formats up to 2 MiB. **Manual** offers WireGuard, VLESS, Shadowsocks, Trojan, Hysteria2, and SOCKS.
2. Choose **Check** and review the type, server, and other details. Credentials stay masked in the review. If an export contains several supported profiles, choose one. For standalone sing-box JSON, omit routing references such as `detour` and `domain_resolver`.
3. For a new connection, review the suggested name and identifier and choose **Save**. Use a unique identifier of up to 32 lowercase letters, digits, hyphens, or underscores, starting with a letter or digit. If the form has expired or the router settings changed, check the profile again before saving.

Open a manual connection by name. Use **Enabled** and **Reserve**, then **Save**. **Check** tests the saved, enabled profile without applying unsaved settings. The page shows the reserve chain, speed, and traffic by site when available. Raw group profiles link to their traffic members.

Choose **Show parameters** only when you need to read credentials on screen, or **Replace parameters** to reopen the wizard for the same identifier. Replacing keeps existing references. **Delete** lists saved references that must be removed before deletion. Disabling a profile keeps its credentials and references while its configured reserves handle traffic. With no enabled reserve, traffic for the disabled profile is blocked. [Fallback chains](routing.md#fallback-chains)

<a name="diagnostics"></a>

## Diagnostics { #diagnostics }

- Read core, interception, DNS, configuration, country database, watchdog, and load status. Use the refresh link for a new status snapshot.
- **Run check** measures HTTP, HTTPS with certificate verification, and a 64 KiB transfer separately. The check uses the current main VPN path without triggering a switch to its reserve. KeenProxy reports when the VPN path is skipped or routing is stopped or paused. Verify the affected app from a device before deciding the issue is resolved.
- Under **Support report**, choose **Download ZIP** with a management account. The archive includes status, build details, and recent errors. Review the archive before sharing it. **Copy** copies the build identity. [Diagnostic ZIP contents](troubleshooting.md#download-the-diagnostic-zip)
- Under **Updates**, check for a release, install it, or roll back to the recorded previous version. Confirm the version and wait for the service to come back. If you enable **Install automatically**, save a time in the router's time zone. [Update and rollback requirements](getting-started.md#update-from-the-panel)

## Save changes { #save-changes }

**Routing**, **Devices**, and the connection settings forms apply their changes when you select **Save**. **Overview** applies the main switch and main connection directly. If another window has changed the settings since you opened a form, review the current settings and save again. KeenProxy declines the stale submission.

## Recover access through SSH { #ssh-tunnel }

From a computer on your LAN, forward a local port to the panel's loopback listener on the router. Replace `ROUTER` with its SSH hostname or LAN address. This example uses the Entware SSH port and the default panel port.

```sh
ssh -N -p 222 -L 127.0.0.1:8086:127.0.0.1:8086 root@ROUTER
```

On OpenWrt, omit `-p 222` if SSH uses its default port. Keep the tunnel open and visit `http://127.0.0.1:8086`. The loopback address grants management access over the tunnel. The router listener must accept loopback connections. If its port differs, use that port on the router side of the forward. [Sign-in recovery and service configuration](troubleshooting.md#recover-access)

## Configuration and backups { #configuration-and-backups }

The Entware configuration is `/opt/etc/keenproxy/config.yaml`. Native OpenWrt uses `/etc/keenproxy/config.yaml`. Back it up privately before editing DNS, interfaces, the listener, or advanced rules. It contains subscription links and connection credentials. KeenProxy reads it at service startup. [Installation paths and service commands](getting-started.md) · [Loopback control API](development.md#control-api)

### Soft memory limit { #soft-memory-limit }

Use `system.memory_limit_mib` in YAML to set a soft Go memory recommendation for KeenProxy and its embedded engine. The value is a positive integer in MiB. A lower value may increase garbage collection and reduce throughput. Leave headroom for the firmware and other services. [Go memory-limit guide](https://go.dev/doc/gc-guide#Memory_limit)

```yaml
system:
  memory_limit_mib: 400
```

Omit the key to use the inherited Go limit, including `GOMEMLIMIT=off`. With no inherited limit, KeenProxy uses 768 MiB. This recommendation can be exceeded and does not cap process RSS.

## Connection compatibility { #connection-compatibility }

### AmneziaWG profiles (experimental lx build)

Import a single-peer AmneziaWG `.conf` file or paste its contents in the connection wizard. AWG fields select **AmneziaWG** automatically. KeenProxy stores the original profile when you save the connection. Keep the file private because it contains the tunnel's private key and may contain a preshared key.

This build embeds [sing-box-lx 1.14.4-lx.35](https://github.com/Leadaxe/sing-box-lx/releases/tag/v1.14.4-lx.35). It supports AWG 2/3 client parameters and application TCP/UDP through a userspace WireGuard endpoint; the outer tunnel uses UDP. No kernel AWG module or additional daemon is required. Unsupported fields, executable hooks and multiple peers are rejected instead of being silently discarded.

For a standalone Amnezia `vpn://` client export, paste the complete link or upload a text or `.vpn` file containing it. KeenProxy decodes the export locally. If it contains several AWG profiles, select one and choose **Check** again. Review the name and ID, then save the selected AWG client configuration.

Compressed and uncompressed standalone exports with supported format versions (missing, 0 or 1) are accepted. The encoded URI is limited to 2 MiB and decoded JSON to 1 MiB. An export may contain at most 32 AWG candidates, with at most 1 MiB of native profile text in total; an over-limit export is rejected as a whole, without partial import. Damaged exports, unsupported protocol options, service/subscription keys and administrator-only exports without client keys are rejected. A `vpn://` link is not necessarily a ready-to-use tunnel: obtain a **client connection export**, not a subscription activation key.

To bound router memory use, junk bursts are limited to 256 packets and 1 MiB of worst-case payload per handshake. The same budget applies to native AWG profiles and core-decoded raw WireGuard endpoints.

The profile's `DNS` setting does not replace KeenProxy DNS settings. Existing routing rules and failover still select the connection; `AllowedIPs` does not install system routes. Application UDP requires **TPROXY** interception. The existing participant **UDP/443 rejection remains enabled**, so importing AWG does not enable client QUIC traffic. Amnezia subscription activation, server provisioning and service API integration are not supported.

For YAML configuration, store the profile as a block scalar:

```yaml
connections:
  - id: awg
    name: AmneziaWG
    type: amneziawg
    amneziawg: |
      [Interface]
      PrivateKey = <client-private-key-base64>
      Address = 10.77.0.2/32
      Jc = 3
      Jmin = 40
      Jmax = 80
      S1 = 20
      S2 = 30
      H1 = 1001
      H2 = 1002
      H3 = 1003
      H4 = 1004
      [Peer]
      PublicKey = <server-public-key-base64>
      Endpoint = vpn.example.com:51820
      AllowedIPs = 0.0.0.0/0
```

Replace the placeholders and obfuscation values with those exported by your server. Before rolling back to an official-sing-box build, remove or replace AmneziaWG connections and save the configuration so the older engine can load it.

### sing-box-lx compatibility { #sing-box-lx-compatibility }

Both builds support XHTTP and native TrustTunnel alongside existing VLESS, REALITY and AWG. Paste server-exported links or a single raw sing-box outbound in the connection wizard. Choose **Check**, review the profile and choose **Save** to apply it.

VLESS links retain their `encryption` setting instead of silently discarding it. REALITY's hybrid key exchange and VLESS encryption are different mechanisms; neither adds support for Xray's `pqv` signatures or `spiderX`. Use parameters matching the server rather than enabling encryption arbitrarily.

Supported link parameters include:

| Feature | Parameters |
| --- | --- |
| XHTTP | `type=xhttp` or `splithttp`, `host`, `path`, `mode=auto/packet-up/stream-up/stream-one`, URL-encoded `extra` JSON and `xmux` |
| VLESS encryption | `encryption=mlkem768x25519plus.…`; `none` leaves this layer disabled |
| REALITY | `key_share=hybrid` or `classical` (alias `keyShare`), alongside `pbk`, `sid`, `sni` and `fp` |
| TLS fragmentation | Explicit boolean `fragment`, `record_fragment` (alias `recordFragment`), and duration `fragment_fallback_delay` (alias `fragmentFallbackDelay`) |

Malformed flags, unsupported XHTTP options, non-empty `pqv`/`fm` and custom `spx` values fail import. Raw sing-box JSON remains available for engine-supported options without a share-link mapping; Apply performs engine validation.

XHTTP (`type=xhttp` or `splithttp`) with `flow=xtls-rprx-vision` requires an enabled VLESS `encryption` layer. Links with this combination and missing or `none` encryption are rejected at import; TLS/REALITY alone does not make it compatible. Encrypted XHTTP/Vision profiles remain supported.

The full build includes QUIC/HTTP/3. Lite keeps TCP/TLS transports, including XHTTP over HTTP/1.1 or HTTP/2 and TrustTunnel over HTTP/2; HTTP/3-only profiles require the full build. This engine-side transport choice does not change participant UDP/443 interception policy.

TrustTunnel uses `type: link` with the complete exported `tt://?…` link. Legacy `type: trusttunnel` sections are normalized when loaded and saved in the link representation on Apply; `binary` and `socks_port` no longer control a process. Previously installed external clients are left untouched but are not used. Keep an old configuration backup before migration if you need to return to an external-client build.

Upgrades and `--uninstall` leave legacy `bin/trusttunnel_client` and `share/keenproxy/trusttunnel/` files under the installation prefix (normally `/opt`). After confirming that the native connection works, remove these files manually only if no other service uses them and you no longer need an external-client rollback. Back up the old configuration first; generated client files may contain credentials.

The status API no longer returns the `trusttunnel` external-process field. External consumers must stop requiring that field; the native outbound does not have a separately supervised client process.

```yaml
connections:
  - id: tt
    name: TrustTunnel
    type: link
    link: "tt://?REPLACE_WITH_EXPORTED_LINK"
```

The placeholder is not a usable credential. TLS certificate verification stays enabled unless the imported profile explicitly disables it. If an exported option cannot be represented by the embedded implementation, import reports an error rather than silently weakening the profile.

Native TrustTunnel import rejects client-random authentication fields, subscription URLs, differing address ports and unsupported transports. Same-port IP lists use one address (IPv4 preferred), not the external client's address racing. HTTP/2 anti-DPI maps to TLS fragmentation; its packet timing is not identical to the external client. HTTP/3 with anti-DPI is rejected. Link DNS settings do not replace KeenProxy's DNS ownership.

For a link listing several IP addresses on the same port, import selects the first IPv4 address in exported order, otherwise the first IP address. The remaining addresses are not retained as automatic fallbacks: if the selected endpoint fails, the embedded client does not try the other exported addresses.

When certificate verification is enabled, `custom_sni` must match the exported `hostname` (case and a trailing dot are ignored). The native TLS schema cannot transmit one SNI while verifying a different hostname; such profiles are rejected rather than authenticating the wrong identity. This does not automatically disable verification.
