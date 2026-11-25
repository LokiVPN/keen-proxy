# User guide

!!! note "Server-rendered interface preview"
    The panel opens [first-run setup](#first-run) on a fresh configuration. After setup, `/` opens the overview. The Connections tab shows saved subscriptions and manual connections. For settings beyond this preview, edit the [YAML file](getting-started.md) or use the loopback [control API](development.md#control-api). Other sections of this guide still describe parts of the previous panel.

The screenshots below are synthetic.

## Access the panel

After a successful installation or command-line update, the installer prints the panel URL. Browser sign-in uses KeeneticOS sessions (see [KeeneticOS sign-in](development.md#keenetic-auth)); the HTTP API itself accepts only local processes on the router. You can display the URL again with `keenproxy --url`, which reads the existing configuration without starting the daemon or changing its settings. For a non-default configuration:

```sh
keenproxy --url --config /path/to/config.yaml
```

The URL follows `api.listen`; wildcard listeners (`0.0.0.0` or `::`) use the first private IPv4 address of the configured LAN interface, the same address KeeneticOS sign-in accepts. If that interface has none, no address is guessed. A loopback listener remains accessible only from the router or through a suitable SSH tunnel. See [installation and updates](getting-started.md#install-or-update-from-github).

### Use an existing KeeneticOS session

With [KeeneticOS sign-in enabled](development.md#keenetic-auth), sign in to the
router with a management account and select **Open panel** on the KeenProxy
card in **Applications**. Use the router's local IP address. When your session
ends, the panel returns to a sign-in screen with a link to KeeneticOS.

## First run { #first-run }

Open KeenProxy with a router management account. Paste the HTTPS subscription link from your LokiVPN account, then choose **Check**. KeenProxy sends its stable device ID to the provider. This can use a slot on your subscription. The check shows the supported servers, provider message, and any usage, expiry, or routing information the provider supplies. Routing details describe the provider profile. KeenProxy evaluates its rules when you enable the subscription.

On a router without a saved network policy, choose **Enable** to save the subscription and set split routing for the home network detected on the configured LAN interface. The network follows the provider profile. If the provider supplies no routing profile, unmatched traffic goes through the subscription. The first setup needs a private IPv4 address on that interface.

If you already have network policies, choose **Set up subscription** on **Overview**. Check the link and choose **Add subscription** to make its servers available in the main connection menu while keeping your current routing policies.

On **Overview**, choose **Replace link** to reopen setup. Check the new link and confirm **Replace link** to update the saved subscription. The subscription keeps its ID and reserve, and your existing routing, devices, and paused state stay in place. View-only accounts can open the setup page with its controls disabled.

## 1. Read the overview

**Overview** shows the main connection status, subscription usage and expiry when supplied by the provider, and the last and next scheduled updates. A warning appears when the subscription is due to expire within seven days. **Update now** queues a subscription refresh. If an update fails, the overview reports the failure alongside the latest known expiry. The device count shows how many detected LAN devices are covered by KeenProxy's current routing plan. The routing and device summaries link to their tabs.

When subscription nodes are unavailable, the status line shows the reserve connection in use, including a direct reserve. It shows **No connection** if the active path fails its check or only blocks traffic. This includes the built-in `block` fallback, named block outbounds, and selectors whose leaves only block traffic.

The **VPN traffic** chart shows the last 30 minutes for targets that can send traffic through a tunnel. When a raw sing-box group contains both direct and tunnel members, the overview names the connection and the chart also includes any direct traffic sent by that group.

Use **Enabled** to pause or resume VPN routing for all devices. While paused, all devices connect directly. Under **Main connection**, choose automatic failover, a balancing mode, a specific subscription node, or a manual connection. The selection updates the home network and **All traffic through VPN** routing when it uses the previous main connection.

Changes apply as soon as you use the switch or select a connection. With JavaScript disabled, use **Save** next to the control. View-only accounts can read the overview with its configuration controls disabled.

## 2. Configure a connection

Open **Connections**. The **Manual connections** table shows each profile's protocol, latest check result, and configured [reserve chain](routing.md#fallback-chains). Use **On** to enable or disable a profile. Choose **Save** to apply the switches and subscription reserves, or **Cancel** to return to the saved settings. Router accounts with view access can read the tables with the controls disabled.

Choose **Add connection**. **Paste** detects a share link, standalone Amnezia `vpn://` export, WireGuard or AmneziaWG `.conf`, or sing-box JSON containing one connection profile. **From file** accepts the same formats up to 2 MiB. **Manual** offers WireGuard, VLESS, Shadowsocks, Trojan, Hysteria2 and SOCKS.

Choose **Check** to validate the profile on the router and review its type, server and SNI. The wizard shows **Hidden** when a summary field contains a connection credential. For a new connection the wizard suggests a numbered protocol name, such as `VLESS 2`, and an available identifier, such as `vless-2`. You can edit both before choosing **Save** to apply the connection and return to the list. An identifier starts with a lowercase Latin letter or digit and uses up to 32 lowercase Latin letters, digits, hyphens or underscores. It must be unique and available for manual connections. If the checked draft expires or settings change in another window, check your input again. Replacing a profile reuses its identifier and all routing and reserve references.

If an identifier conflicts with a routing tag, choose another one. After a manual input error, correct the highlighted field and re-enter credentials before checking again.

Import a standalone sing-box outbound or endpoint. Check refuses explicit tag references such as `detour` and `domain_resolver`, including references to tags declared in the same JSON. KeenProxy configures routing, DNS resolution and interface binding.

Select a manual connection's name to open its details. Use **Enabled** and **Reserve**, then choose **Save**. The page shows the reserve chain. The list of available reserves stays the same as you change the switch. **Check** and **Save** validate the two settings together. If the combination would create a routing cycle, the error appears below **Reserve** and both edits stay on the form. **Check** also tests the saved profile's reachability through the configured failover URL when the saved profile is enabled.

**Speed** and **Traffic by site** show recorded traffic for that connection, with up to 30 minutes of speed history. Raw selectors list their members and link to saved connection pages. Traffic through built-in **Direct** or **Block** members is attributed outside connection pages.

The page masks credentials and hides facts that repeat other profile values, including encoded values. A managing account can choose **Show parameters** for the current page or **Replace parameters** to reopen the wizard for that connection. Replacing a profile keeps its traffic history. **Delete** lists any saved references that must be removed before deletion. Once deletion takes effect, a connection created later with the same identifier starts with empty traffic history.

Disabling a connection keeps its profile, credentials, and routing references. Its tunnel and availability checks stop. Profiles can also be set in the [YAML configuration](getting-started.md).

Groups, devices, networks, and DNS settings keep their references to a disabled connection. Traffic follows its configured enabled fallback chain; with no enabled fallback it is blocked, not silently routed directly or passed to the next rule. An explicitly configured **Direct** fallback remains intentional. DNS keeps its separate strict/direct failure policy: disabling a connection must not create a direct DNS path in strict mode.

In the YAML configuration, raw sing-box profiles keep their `detour` and selector references to the configured connection ID. When that connection is disabled, its runtime relay uses the same enabled fallback chain, or blocks if none is available; the saved raw profile is not rewritten.

### Native subscriptions { #native-subscriptions }

Set up or replace a subscription as described in [First run](#first-run). KeenProxy accepts HTTPS Xray share lists in plain text or Base64, up to 2 MiB and 256 distinct nodes. For a provider that requires a specific client, use its Xray share-list URL or enable KeenProxy in the provider settings.

The subscription's section on **Connections** shows the catalog status, the latest HTTPS result for each node, and any notice about the selected provider's routing rules. Choose **Check** for one node or **Check all nodes** for the catalog. KeenProxy queues the checks and updates the results as they arrive. Your staged reserve and switch edits stay on the form until you choose **Save** or **Cancel**. The successful duration includes connection setup. The probe uses the configured HTTPS check URL or its default endpoint and verifies the server certificate.

Under **Reserve if none of the nodes respond**, choose a manual connection, **Direct — without VPN**, or **None — block VPN traffic**, then choose **Save**. A manual reserve follows its configured chain if its own tunnel is disabled. **No reserve configured** preserves an existing unset reserve.

Choose a subscription target under **Main connection** on **Overview**.

- A specific node stays fixed. The route blocks if the node disappears from the subscription, unless the subscription has a [reserve](routing.md#subscription-reserve), which then takes the traffic.
- **Auto — switch nodes on failure** starts in provider order and switches after sustained failure of the active node. By default, checks run every 15 seconds and the failure window is 60 seconds. A working replacement stays selected when a preferred node recovers. **Current** identifies the selected node while **Unavailable** reports a failed check. A row can show both.
- **Balancing by rotation** cycles through eligible nodes for successive new connections.
- **Balancing by site** assigns each site to the same eligible node across devices. It uses the registrable domain when available and the destination IP otherwise.
- **Balancing by session** keeps the same eligible node for each device IP and site pair, up to 1,024 pairs per subscription. The assignment expires after 30 minutes of inactivity or when that node stops being eligible.

The three balancing modes use nodes that passed their latest check and support the connection's transport. If no eligible node supports the transport, new connections use the subscription's [reserve](routing.md#subscription-reserve) when one is set, or are blocked.

Choose **Update now** on **Overview** to fetch the provider's latest list and metadata. If the fetch fails, KeenProxy retains its last validated list and reports the update status. Keep subscription URLs private. They are included in full YAML backups.

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

### sing-box-lx compatibility

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



## 3. Add a routing group

Open **Rules → Whitelist**. Create a group, name it, select its target connection (or **Direct**/**Block**), and add domains or addresses. For example, direct `work.example.com` to the Netherlands profile. Review imported entries before confirming; country selectors express broader policies.

To move several domain or country groups together, select their checkboxes, choose a target in **Change route**, and review the preview. Groups hidden by a filter can still be selected. Choose **Save to draft**, then **Apply** when ready.

Expand an entry to see its current DNS observations and expiration. A resolved address alone does not prove that application traffic followed the intended tunnel.

Use the on/off switches to pause an entire group or an individual domain/IP rule without removing its value. Country/category groups also have group and per-selector switches. Disabled items remain visible; the active/total counts distinguish saved rules from effective rules. Turning a group off preserves its children's individual states, so turning it on again does not re-enable rules you had paused separately.

An off group or rule is skipped, not blocked: the remaining rules and device policy determine the route. In particular, disabling a block rule stops that rule from blocking. Off domain rules do not contribute active DNS rule sets or initiate background resolution. A country/category group with no active selectors is inactive even in **All except** mode; it never becomes a match-all rule. Review the shared draft and **Apply** to change live behavior.

In YAML, connection and group switches use `disabled: true`. Per-rule states are retained in `disabled_entries`, `disabled_countries`, and `disabled_categories`; the original entries/selectors remain present. Missing fields preserve the previous enabled behavior. Older releases reject unknown activation fields: prepare and validate a compatible configuration before downgrading. Removing the fields re-enables the corresponding items, so review the resulting routes first.

![Domain groups, targets, and address observations](../assets/screenshots/en-rules.png)

See [Country rules](routing.md#country-rules) for an illustrated setup, country exclusions, and rule precedence.

## 4. Choose devices and networks

Open **Devices**. The list includes devices discovered on the LAN and saved devices that are offline. A manually assigned name takes priority over a discovered name. You can identify an unnamed device by its MAC address.

Turn on **VPN** for a device to use the selected routing rules. Turn it off to bypass KeenProxy interception. **Enable for all** skips devices that need a VPN target for the change and shows how many it skipped. **Disable for all** switches off every listed device. A device using a full tunnel, including one that inherits it from its network, keeps that mode until you edit its switch or a bulk action changes it.

**New devices use the VPN right away** sets the default for the home network. When you select **Save**, KeenProxy records the displayed switches, including off states on skipped devices, so listed devices keep their states when the default changes. Save also checks each device’s current address for split routing. If an address has moved outside VPN coverage, review the marked devices before saving again.

## 5. Review and Apply

The change bar appears whenever the draft differs from the saved configuration. Review changes across screens, then choose **Apply** once. Wait for success. If validation/application fails, read the error and correct the draft. **Discard** restores the last saved snapshot.

![A pending change with shared Apply and Discard controls](../assets/screenshots/en-apply.png)

## 6. Verify the result

Open **Diagnostics → State** to see whether the core and DNS listener are running, the interception mode, when configuration was applied, the country database, firewall repairs since startup, and CPU and RAM for the router and KeenProxy.

Choose **Run check** to test HTTP, HTTPS with certificate verification, and a 64 KiB transfer through the applied main connection. The check uses a single selected outbound. It requires an outbound that can be dialed without a detour or reserve. The results show the subscription node tested and the time of the check. The DNS row describes the listener. Use [a test from the affected device](network-flow.md#how-to-trace-one-request) to verify its DNS and traffic paths.

### Export journals and diagnostics { #export-journals }

With a management account, open **Diagnostics → Support report → Download ZIP**. See [what the download contains and what to review before sharing](troubleshooting.md#download-the-diagnostic-zip).

Watchdog recovery events include the failed firewall check and the verification result. The ZIP retains safe structured evidence. See [watchdog diagnostics](troubleshooting.md#why-does-the-watchdog-restore-interception-rules).

### Inspect one routing decision

Open **Logs** and switch between **Routing**, **Audit**, and **System**. In **Routing**, **Group repeats** combines matching loaded records in 30-second windows. Expand a group to see its members or clear the checkbox for individual entries. Search and filters narrow the view. A routing record explains which outbound was selected. Check the application separately to confirm that the connection and transfer succeeded. New routing records in the browser demo are generated locally by the simulation.

![Routing journal with synthetic records](../assets/screenshots/en-journal.png)

## 7. Find settings and manage backups

Open **Settings** with the gear icon. On narrow screens, choose a section from the dropdown. **DNS** opens by default. Use **YAML configuration** to manage backups. Use **Network and interception** for REDIRECT/TPROXY and interfaces, **Panel access** for the listener, and **Country databases** for GeoIP status. Use **Language and theme** for browser preferences. Routing and access changes use the shared **Apply** action. Changing the panel listener also requires a service restart. **Updates** has its own controls.

Open **Settings → DNS** to choose the primary DNS server. The secondary is optional; clear its selection to remove it. Choose a provider and protocol from the list or select **Custom DNS server** and enter an IP address or a DoH, DoT, or UDP URL. The provider list includes Cloudflare, Google Public DNS, Quad9, AdGuard, Yandex DNS, Cisco OpenDNS, CleanBrowsing, and Control D. Each choice shows its filtering policy. KeenProxy tries the primary first and uses the secondary, if configured, when the primary is unavailable. The two servers must be different. **Advanced settings** contains any additional resolvers, bootstrap addresses, and the listening address. The DNS route and tunnel failure policy are configured separately. Imported YAML can also list just one server in `dns.upstreams`.

If you clear **Secondary DNS** while additional servers are configured, the first additional server moves into that slot. The other servers keep their priority order. To keep only the primary, remove all additional servers before clearing the secondary, then choose **Apply**.

If a LAN DNS forwarder's own queries are being redirected back to it, open **Advanced settings → Bypass DNS interception for source IPs**, add the forwarder's own IPv4 address (not its upstream's address), and choose **Apply**. To restore interception, remove the address and Apply again. See [DNS interception exceptions](routing.md#dns) for the YAML key and scope.

The configuration is a YAML file on the router. You can back it up or edit it by hand over SSH; keep copies private because they contain connection credentials. KeenProxy reads the file when it starts.

### Soft memory limit

Open **Settings → System** only if the router is running short of memory. **Soft Go memory limit, MiB** is an optional recommendation for the Go runtime, covering KeenProxy and its embedded sing-box. Lowering it makes garbage collection more frequent, increases CPU usage, and may reduce connection speed. Leave it empty if the router has no memory problems.

This is not a hard cap on process RSS and does not include all memory used by the operating system. Go may exceed the recommendation; leave room for the router firmware, network buffers, and other services. See the [Go memory-limit guide](https://go.dev/doc/gc-guide#Memory_limit).

Use the shared **Apply** button to save and activate the value. A memory-only change does not require restarting the service or sing-box; the saved setting is also applied at startup. An empty field uses the Go limit set before daemon startup, including `GOMEMLIMIT`; if no limit was set, KeenProxy uses **768 MiB (805306368 bytes)**. An explicit value in the panel takes priority. Clearing the field and applying restores this default mode. An explicitly supplied `GOMEMLIMIT=off` is respected and keeps the inherited mode unlimited.

For example, an explicit recommendation of 400 MiB is stored as:

```yaml
system:
  memory_limit_mib: 400
```

Only positive whole MiB values are accepted. To remove the override, omit `memory_limit_mib`, rather than setting it to zero.

## 8. Install or roll back a release

**Diagnostics → Support report** shows the running release, build variant, architecture, and short commit hash. Choose **Copy** to copy the build identity. A local build may lack a release tag or commit hash. The diagnostics ZIP includes the same information in `status.json`.

Open **Diagnostics → Updates** to check for releases, install an available update, or roll back to the previous version when recorded. Confirm the version on the next screen and wait for the service to reconnect. To schedule installation, enable **Install automatically**, choose a time in the router's time zone, and save. See [the update guide](getting-started.md#update-from-the-panel) for first-time setup and rollback requirements.
