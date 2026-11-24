# Routing and DNS

For diagrams of interception, DNS, and route selection, see [How traffic flows](network-flow.md).

## Routing tab

Choose how the home split policy handles traffic and select **Save** to apply the changes.

- **By subscription rules** uses the provider's rules and its default for unmatched traffic. The option is unavailable when the provider withholds its rules. The table groups rules by their action. Site and address lists each have one switch for their literal entries. Unavailable rules show a reason.
- **All traffic through VPN** uses the main connection for unmatched traffic. Add exceptions under **Always direct**.
- **Only my sites** sends unmatched traffic directly. Enter sites for the main connection under **Always through VPN**.

Both lists are visible in every mode. Enter one domain, IP address, or subnet per line. Domains include their subdomains. Your lists take priority over provider rules. A line error or the same entry in both editable lists stops the save. Groups with advanced settings are read-only on this tab and their entries don't count toward that check. Rules you switched off stay off when you return to the subscription mode. A direct or blocking main connection makes the VPN option unavailable. If a subscription has no nodes for the selected target, the option follows the [reserve](#subscription-reserve) used for that target. Additional configured groups keep their existing routes and ordering, and device policies continue to determine which devices use these settings.

## Policy building blocks

| Item | Purpose |
| --- | --- |
| Connection | A named tunnel/proxy profile that can be selected as a target |
| Group | A domain/address list or country selector with a target |
| Direct | Connect without a configured tunnel |
| Block | Reject matching traffic |
| Network | Default policy for a subnet |
| Client | Per-device policy identified by MAC address |

Country **Except** selectors describe traffic outside the listed countries. Explicit domain lists and country rules express different levels of policy; inspect the routing journal to confirm which rule actually won for a request.

A disabled group, domain/IP entry, country, or category selector is skipped while its saved value is retained. Later matching rules and the source policy still apply. If every geo selector is off, the group is inactive even with **Except** enabled.

## Country rules

Country groups match the **destination IP address** against the GeoIP database. They do not inspect the visitor's nationality, the website's language, or its domain suffix. A country selection also does not select an exit server: the **Connection** column chooses the route separately.

### Send everything except Russia through a tunnel

1. Create or import a working connection, then open **Rules → Whitelist**.
2. Choose **By country**. A new group starts with Russia (`RU`) selected and **All except these** enabled. Select the group name to rename it if needed.
3. In **Countries**, keep `RU`, or add more countries to exclude. Use **Only these countries** instead to match just the selected countries.
4. Set **Connection** to the desired profile, for example **Finland WG**. **Direct** bypasses the tunnel; **Block** rejects matching traffic.
5. Open **Connections → Clients** and ensure the relevant network or device uses **Split**. Review the shared draft and choose **Apply** once.

[![Country group excluding Russia and targeting Finland WG](../assets/screenshots/en-countries.png)](../assets/screenshots/en-countries.png)

Open the country selector to search by country name or ISO code. Selected countries appear as code chips; removing a chip changes the draft.

[![English country selector with Russia selected](../assets/screenshots/en-country-picker.png)](../assets/screenshots/en-country-picker.png)

### Understand which rule wins

Global block groups are evaluated first. For a routed device/network policy, explicit domain and address groups precede country groups. Device overrides take precedence over network defaults. **Full tunnel** uses its selected default connection and is a different policy from this split-routing recipe.

| Example configuration | Result |
| --- | --- |
| A Steam domain matches **Steam direct** | Direct, even if its destination is outside Russia |
| A domain matches **Video and social media** | Netherlands Reality, before the broad country rule |
| No earlier rule matches and the destination is outside `RU` | Finland WG |
| No earlier rule matches and the destination is in `RU` | The country exclusion does not match; the split policy falls back to Direct |

**All except these** is an inverted match, not a command that forces selected countries to Direct. An earlier explicit rule may still route a Russian destination through another connection. Keep specific exceptions in domain/address groups.

### Check the result

On a real installation, confirm that the country database is loaded in **Diagnostics**, Apply the configuration, and inspect **Logs → Routing** for the selected outbound and matching rule. Missing GeoIP data must be resolved before relying on country routing. CDN addresses and database updates can change an IP's assigned country; use explicit domains or addresses when that distinction matters.

## Country databases

Country selectors use MMDB country databases, managed in **Rules → Country databases**. The list order is priority: the first enabled database that knows an address decides its country, and country rules follow the same precedence. Built-in sources can be enabled, disabled, and reordered. You can also add a custom database: an HTTPS link to `.mmdb`, `.mmdb.gz`, or `.tar.gz` (`{month}` expands to `YYYY-MM` and falls back to the previous month), or an absolute file path on the router.

The router checks enabled databases daily. Files are downloaded over HTTPS only, checked against a published SHA-256 digest when the source has one, validated as a country MMDB, and then swapped in atomically. A failed download keeps the previous file and is retried after 10 minutes, with the delay doubling up to 6 hours. Changing the database list triggers a check right after **Apply**.

Category databases are a second kind of IP database. Instead of countries, they label networks, for example `RU-BLOCKED`, `RE-FILTER`, or `TELEGRAM`. They never take part in country lookups. Groups select labels under **Categories**, alone or together with countries and **All except these**. Enabled category databases are combined, so a label matches if any of them reports it. The built-in runetfreedom sources publish each network under a single label, so a network that appears in several upstream lists matches only one of them. Category groups require at least one enabled category database.

## Fallback chains { #fallback-chains }

A connection can point to another connection or Direct as its immediate fallback. The interface displays the resulting chain. Edit the selected profile's immediate fallback; downstream inherited edges belong to their own profiles. Avoid cycles. Choosing Direct as a fallback intentionally allows a direct path when the primary connection fails.

Disabling a connection keeps its incoming group, client, network, and DNS references. Disabled chain members are skipped in favor of enabled configured backups, but the referring rule itself is not skipped. If none remain, traffic is blocked. There is no implicit Direct fallback. A disabled tunnel or external client is not started and is not health-probed. Re-enable it and Apply to restore its saved settings. DNS remains subject to its separate strict/direct failure policy.

Periodic health checks measure HTTP requests, not ICMP ping. They are separate from the manual HTTPS and transfer checks in Diagnostics.

## Default route for split policies { #default-route }

In split mode, traffic that matches no group goes direct. A network can set `default` to send that traffic elsewhere: a connection ID or a managed subscription target tunnels it, `direct` (or empty) keeps it direct, and `profile` follows the [provider rules](#provider-rules): such traffic uses the policy's target, unless the applied provider profile says `GlobalProxy: false`, which keeps it direct. Without provider rules, `profile` uses the target too. `block` is rejected; add a block group instead. Devices in the network that split inherit its default. Groups always win over the default.

Traffic never goes direct just because a target is missing. `profile` needs the network's `target`, and a network without one is rejected. While provider rules are active, every split network needs a `target`, because provider proxy rules use it, and so does a split device unless its address is in a network that has one. Devices with a fixed `ip` are checked when the configuration is saved. A device known only by its MAC address gets its address at run time and cannot be checked, so give it its own `target` if it can be outside such a network.

```yaml
networks:
  - {name: Home, cidr: 192.168.7.0/24, mode: split, default: fi}
```

## Provider rules { #provider-rules }

`provider_rules` applies the routing rules that a subscription's provider sends in its Happ routing profile. `source` names the subscription. `disabled` lists the keys of rules to switch off: `<action>:<entry>`, for example `block:geosite:category-ads`, or `<action>:literals:site` and `<action>:literals:ip` for the domains and addresses the provider lists itself.

```yaml
provider_rules:
  source: provider
  disabled: ["block:geosite:category-ads"]
```

Set `off: true` inside `provider_rules` to turn all provider rules off while keeping `source` and `disabled`. Remove the flag or set `off: false` to use the saved switches again. A `profile` default uses the policy's target while the rules are off.

A category that contains private subscription data has an opaque switch key. Previously saved keys still control their corresponding rules.

The provider sends the profile with each subscription fetch: in the `routing` response header, or, when the header is empty, as a body line `happ://routing/add/<base64 JSON>` or `happ://routing/onadd/<base64 JSON>`. A `routing-enable` header (or body comment) other than `true` or `1` withholds the rules, and `happ://routing/off` means the provider sends none. A profile that cannot be read is reported as a fixed error while the rules already in use stay. KeenProxy applies only the profile's own lists; it does not follow provider updates between subscription refreshes.

Every split policy, for a network or a device, applies the rules after its own groups: first the provider's domain rules in the profile's `RouteOrder` (block, direct, proxy by default), then the DNS-observation fallback for provider domains (see below), then its address rules in the same order, then country groups and the default route. Proxy rules use the policy's own target (a split policy needs one, see [the default route](#default-route)), direct rules go direct, and block rules reject the connection. A domain in two lists follows the list that comes first in `RouteOrder`. Rules without provider data and entries that sing-box cannot use are skipped. Devices that are off and a paused router are not affected.

Entries use Xray syntax. Domain lists accept `domain:` (suffix), `full:`, `keyword:`, `regexp:`, `geosite:<category>` (with an `@attribute` suffix, only the category's domains that carry that attribute) and plain text, which is a keyword. Address lists accept IP or CIDR literals and `geoip:<tag>`. `geoip:private` and `geosite:private` are skipped because private addresses always go direct. The rule status lists up to 50 skipped unsupported entries, including `ext:`, `ext-domain:`, `dotless:`, negated `!` categories, invalid regular expressions, unreadable addresses, and `geosite:` or `geoip:` entries longer than 249 bytes including the prefix. A category whose data file is missing or could not be loaded is shown as unavailable and does not route. The `GlobalProxy` field of the profile decides only the `profile` default route, not these rules.

An evaluated profile with no usable rules still supplies the `GlobalProxy` default. When no profile applies, `default: profile` uses the policy's target.

Provider domain rules also apply to connections without a readable name. KeenProxy learns their addresses only from DNS answers that devices receive through it, and an address follows the rule until the answer's TTL ends: unlike names in your groups, provider names are never resolved in the background. Only domain entries take part in this (`domain:`, `full:` and the domains of geosite categories); keywords and regular expressions need a readable name. These addresses share a cache of 4,096 names with your groups, and provider names give way first when it is full.

For devices on a split policy, KeenProxy itself answers the domain names of provider block rules with `0.0.0.0`, because their routing would reject the connection anyway. A name that routing decides earlier gets the real answer: a name in one of your groups that does not block, and a name that a rule before block in `RouteOrder` lists as a domain, exact name or keyword (regular expressions are not checked here). Full tunnel devices get real answers, because provider rules do not route their traffic. Your block groups block every device as before.

### Data files, limits and refresh { #provider-rules-data }

Categories come from the `Geositeurl` and `Geoipurl` data files that the profile names. KeenProxy downloads them directly (not through a connection), over HTTPS only, following at most three HTTPS redirects (for example from a release download) and never leaving HTTPS, and extracts only the categories the profile references. For downloads and redirects, KeenProxy refuses loopback, private (RFC 1918 and IPv6 ULA), link-local, unspecified and multicast addresses at connect time, including when a hostname resolves to one. A profile is limited to 256 KiB after decoding, each data file to 16 MiB, geosite data to 100,000 domains and geoip data to 200,000 prefixes in total; a file over a limit fails with a fixed message and its rules stay unavailable. Each file has a one-minute download timeout. A profile with only two-letter `geoip:` tags and no geoip file uses the built-in country databases.

Apply spends at most 20 seconds on these downloads and stops 15 seconds before its own deadline; with less than a second left, it skips them. Rules that lack a data file are installed anyway, and the missing files are downloaded again in the background after 1 minute, then 2, 4 and so on up to 1 hour, without refetching the subscription. Data from an unchanged file is reused for up to one week.

The built rules and the profile they came from are saved with the subscription snapshot in the state directory (private, mode 0600) and restored at start before interception begins. For subscriptions that send an HWID, KeenProxy restores cached provider text and rules only when the current installation identity matches the identity used for the fetch. Rules without a match are evaluated again on the next fetch. If a refresh fails after complete rules were built for the same identity, those rules stay in use and the error is shown. A successful attempt replaces incomplete rules. Turning `provider_rules` off frees them.

## Reserve for a subscription { #subscription-reserve }

A subscription can name a reserve with `fallback`: a manual connection ID, `direct` or `block`. For the automatic target, when no node answers for `failover.down_after`, traffic goes to the reserve instead of staying on a dead node. A connection with its own fallback chain keeps that chain while it serves as the reserve. Traffic returns to a node once one has passed its checks for `failover.up_after`. The balancing modes have no such delay: they follow each node's latest check, so they use the reserve as soon as no node's latest check passed (including right after start, before the first check) and return on the first passing check. A pinned node whose node disappeared from the subscription, and a subscription that has no nodes at all, use the reserve directly, without a switch reason. Without a reserve, the automatic target stays on its last node, and balancing, pinned or empty targets block. The subscription status shows the reserve and reports the switch reason `fallback` while it is in use. A subscription cannot be the reserve of another subscription, and connections cannot reference subscriptions.

```yaml
subscriptions:
  - {id: provider, url: "https://provider.example/links/example-token", fallback: home-wg}
```

## Pause and devices that are off { #pause }

A device whose mode is `off` is not touched by KeenProxy: no routing, no blocking and no DNS interception, so its DNS goes straight to the KeeneticOS resolver. Pausing the router (`paused: true`) does the same for every device while the daemon keeps running; unpausing is a normal Apply. DNS interception and the encrypted-DNS guard apply only to devices that take part in a network or client policy.

```yaml
paused: true
```

## DNS

DNS settings choose upstream resolvers and whether requests travel directly or through a connection. Bootstrap addresses help resolve encrypted resolver hostnames. Failure policy controls whether a failed selected path may use direct DNS. Filter lists and exceptions change DNS answers, not every possible form of application traffic.

If KeenProxy uses a resolver on the LAN and that resolver forwards requests through this router on port 53, the router can send them back to the same resolver. In **Settings → DNS → Advanced settings**, add the resolver's source IPv4 address to the DNS interception exceptions and choose **Apply**. This is `dns.bypass_sources` in YAML, for example `bypass_sources: ["192.168.1.100"]` under `dns`. Use a fixed address or DHCP reservation for the resolver. An empty list preserves the default interception behavior.

The exception bypasses KeenProxy for all UDP/TCP port 53 queries from those addresses on the configured LAN interface, including DNS filtering for those queries. It does not affect other clients, application routing on other ports, or encrypted DNS rules. Only add trusted resolvers that need this exception; the router's own forwarding rules still apply.

Use your router's actual network test procedure to evaluate UDP/TCP interception and encrypted-DNS handling. Applications can use their own resolvers. The UI does not establish universal DNS-leak protection.

See the [user guide](user-guide.md) for screenshots and [Troubleshooting](troubleshooting.md) for interpreting evidence.
