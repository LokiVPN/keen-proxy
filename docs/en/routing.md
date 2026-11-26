# Routing and DNS

For diagrams of interception, DNS, and route selection, see [How traffic flows](network-flow.md).

## Routing tab

Choose how the home split policy handles traffic and select **Save** to apply the changes.

**Rules from subscription** selects one configured subscription as the source for provider rules. Use **Review source** to see the selected source's availability before saving. The source and main connection are separate settings. Saving a change to the source clears the previous source's rule switches.

- **By subscription rules** uses the provider's rules and your choice under **Remaining traffic**. The option is unavailable when the provider withholds its rules. The table groups rules by their action. Site and address lists each have one switch for their literal entries. Unavailable rules show a reason.
- **All traffic through VPN** uses the main connection for unmatched traffic. Add exceptions under **Always direct**.
- **Only my sites** sends unmatched traffic directly. Enter sites for the main connection under **Always through VPN**.

Under **Remaining traffic**, **Directly** (`default: direct`) is the starting choice for setup and for a reset that recreates the Home policy. **Through VPN** uses the main connection. **As the subscription says** (`default: profile`) shows the current provider default when the profile is available and follows it as the subscription refreshes. If no profile applies, this choice uses the main connection. Existing configurations keep their saved defaults until you change them.

Both lists are visible in every mode. Enter one domain, IP address, or subnet per line. Domains include their subdomains. Your lists take priority over provider rules. A line error or the same entry in both editable lists stops the save. Groups with advanced settings are read-only on this tab and their entries don't count toward that check. Rules you switched off stay off when you return to the subscription mode with the same source. If that subscription withholds rules, you can keep the saved mode while editing your lists. A direct or blocking main connection makes the VPN option unavailable. If a subscription has no nodes for the selected target, the option follows the [reserve](#subscription-reserve) used for that target. Additional configured groups keep their existing routes and ordering, and device policies continue to determine which devices use these settings.

## Policy building blocks

| Item | Purpose |
| --- | --- |
| Connection | A named tunnel/proxy profile that can be selected as a target |
| Group | A domain/address list or country selector with a target |
| Direct | Connect without a configured tunnel |
| Block | Reject matching traffic |
| Network | Default policy for a subnet |
| Client | Per-device policy identified by MAC address |

Country selectors with `except: true` match addresses outside the listed countries. Check the routing journal to confirm which rule handled a request.

A disabled group, domain/IP entry, country, or category selector is skipped while its saved value is retained. Later matching rules and the source policy still apply. If every geo selector is off, the group is inactive even with `except: true`.

## Country rules

Configure country groups in YAML. The GeoIP database classifies the destination IP address. The group's `target` selects the connection, `direct`, or `block`.

### Send everything except Russia through a tunnel

1. Create or import a working connection on **Connections**. Use its ID in place of `fi`.
2. Merge the group and policy below into the existing `groups` and `networks` sections. Adapt the existing network entry for your LAN and replace the example CIDR with its actual subnet. If a device overrides that policy, make sure it also uses `mode: split`.
3. Validate and restart the service. [Edit and reload YAML](user-guide.md#edit-and-reload-yaml)

```yaml
groups:
  - name: outside-ru
    target: fi
    countries: [RU]
    except: true
networks:
  - name: Home
    cidr: 192.0.2.0/24
    mode: split
    target: fi
    default: direct
```

Add ISO country codes under `countries` to exclude more countries from the group. With `except: false` the group matches the listed countries.

### Understand which rule wins

Global block groups are evaluated first. In split mode, explicit domain and address groups and any active provider rules precede country groups. Device overrides take precedence over network defaults. A full-tunnel policy uses its selected connection for the default route.

| Example configuration | Result |
| --- | --- |
| A Steam domain matches **Steam direct** | Direct, even if its destination is outside Russia |
| A domain matches **Video and social media** | Netherlands Reality, before the broad country rule |
| No earlier rule matches and the destination is outside `RU` | Finland WG |
| No earlier rule matches and the destination is in `RU` | The country exclusion does not match; the split policy falls back to Direct |

An earlier explicit rule may still route a Russian destination through another connection. Use domain/address groups for specific exceptions.

### Check the result

After the restart, check **Country database** under **Diagnostics → State**. Once the database is loaded, test destinations inside and outside the listed countries from an affected device and check the selected outbound and matching rule. CDN addresses and database updates can change an IP's assigned country. Use explicit domains or addresses for endpoints that must use a specific route. [Inspect local journals](troubleshooting.md#inspect-local-journals)

## Country databases

Manage MMDB sources under `geoip.databases` in YAML. The first enabled country database that knows an address determines its country. Reorder the entries to change that priority, or set `enabled: false` to turn an entry off. The example enables the built-in DB-IP source. For a custom entry, use a unique `id`, `enabled: true`, and a `url` or `file`. A URL must use HTTPS and can point to `.mmdb`, `.mmdb.gz`, or `.tar.gz`. The placeholder `{month}` expands to `YYYY-MM` and falls back to the previous month. A file path must be absolute on the router. [Edit and reload YAML](user-guide.md#edit-and-reload-yaml)

```yaml
geoip:
  databases:
    - id: dbip
      enabled: true
```

KeenProxy checks enabled databases at startup and daily. Downloaded files are checked against a published SHA-256 digest when available, validated as MMDBs, and swapped in atomically. A failed download keeps the previous file and is retried after 10 minutes, with the delay doubling up to 6 hours. After the restart, confirm that the country database has loaded under **Diagnostics → State**.

Category databases label networks with names such as `RU-BLOCKED`, `RE-FILTER`, or `TELEGRAM`. They are queried separately from country databases. Use `groups[].categories` alone or with `countries`. The group matches if either selector matches, and `except: true` inverts that combined match. Category groups require at least one enabled category database. A label matches if any enabled category database reports it. The built-in runetfreedom sources publish each network under a single label, even if it appears in several upstream lists.

## Fallback chains { #fallback-chains }

A connection can point to another connection or Direct as its immediate fallback. The interface displays the resulting chain. Edit the selected profile's immediate fallback; downstream inherited edges belong to their own profiles. Avoid cycles. Choosing Direct as a fallback intentionally allows a direct path when the primary connection fails.

Disabling a connection keeps its incoming group, client, network, and DNS references. The referring rule skips disabled chain members and uses the next enabled backup. If none remain, traffic is blocked. A disabled connection stays stopped and is excluded from health checks. To restore its saved settings, open it on **Connections**, turn on **Enabled**, and choose **Save**. DNS follows its separate strict/direct failure policy.

Periodic health checks measure HTTP requests, not ICMP ping. They are separate from the manual HTTPS and transfer checks in Diagnostics.

## Default route for split policies { #default-route }

In split mode, traffic that matches no group goes direct. A network can set `default` to send that traffic elsewhere: a connection ID or a managed subscription target tunnels it, `direct` (or empty) keeps it direct, and `profile` follows the [provider rules](#provider-rules): such traffic uses the policy's target, unless the applied provider profile says `GlobalProxy: false`, which keeps it direct. Without provider rules, `profile` uses the target too. `block` is rejected; add a block group instead. Devices in the network that split inherit its default. Groups always win over the default.

A `direct` default needs no network target on its own. A `profile` default needs the network's `target`. While provider rules are active, every split network needs a `target` for provider proxy rules. A split device also needs one unless its address is in a network that has one. Devices with a fixed `ip` are checked when the configuration is saved. A device known only by its MAC address gets its address at run time. Give it its own `target` if it can be outside such a network.

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

Set `off: true` inside `provider_rules` to turn all provider rules off while keeping `source` and `disabled`. Remove the flag or set `off: false` to use the saved switches again. A `profile` default uses the policy's target while the rules are off. Removing the source subscription from **Connections** also clears its inactive `provider_rules` block, including `disabled`.

The `disabled` keys belong to one source. When changing `source` in YAML, clear `disabled` to reset the previous subscription's switches. Saving a different source in the panel clears them automatically.

A category that contains private subscription data has an opaque switch key. Previously saved keys still control their corresponding rules.

The provider sends the profile with each subscription fetch: in the `routing` response header, or, when the header is empty, as a body line `happ://routing/add/<base64 JSON>` or `happ://routing/onadd/<base64 JSON>`. A `routing-enable` header (or body comment) other than `true` or `1` withholds the rules, and `happ://routing/off` means the provider sends none. If KeenProxy cannot read a refreshed profile, it keeps any complete rules already in use. KeenProxy applies only the profile's own lists; it does not follow provider updates between subscription refreshes.

Every split policy, for a network or a device, applies the rules after its own groups: first the provider's domain rules in the profile's `RouteOrder` (block, direct, proxy by default), then the DNS-observation fallback for provider domains (see below), then its address rules in the same order, then country groups and the default route. Proxy rules use the policy's own target (a split policy needs one, see [the default route](#default-route)), direct rules go direct, and block rules reject the connection. A domain in two lists follows the list that comes first in `RouteOrder`. Rules without provider data and entries that sing-box cannot use are skipped. Devices that are off and a paused router are not affected.

Entries use Xray syntax. Domain lists accept `domain:` (suffix), `full:`, `keyword:`, `regexp:`, `geosite:<category>` (with an `@attribute` suffix, only the category's domains that carry that attribute) and plain text, which is a keyword. Address lists accept IP or CIDR literals and `geoip:<tag>`. `geoip:private` and `geosite:private` are skipped because private addresses always go direct. Unsupported entries are skipped, including `ext:`, `ext-domain:`, `dotless:`, negated `!` categories, invalid regular expressions, unreadable addresses, and `geosite:` or `geoip:` entries longer than 249 bytes including the prefix. The Routing page shows available rule groups and a reason beside unavailable categories. Connections shows the subscription's overall rules status. The `GlobalProxy` field of the profile decides only the `profile` default route, not these rules.

An evaluated profile with no usable rules still supplies the `GlobalProxy` default. When no profile applies, `default: profile` uses the policy's target.

Provider domain rules also apply to connections without a readable name. KeenProxy learns their addresses only from DNS answers that devices receive through it, and an address follows the rule until the answer's TTL ends: unlike names in your groups, provider names are never resolved in the background. Only domain entries take part in this (`domain:`, `full:` and the domains of geosite categories); keywords and regular expressions need a readable name. These addresses share a cache of 4,096 names with your groups, and provider names give way first when it is full.

For devices on a split policy, KeenProxy itself answers the domain names of provider block rules with `0.0.0.0`, because their routing would reject the connection anyway. A name that routing decides earlier gets the real answer: a name in one of your groups that does not block, and a name that a rule before block in `RouteOrder` lists as a domain, exact name or keyword (regular expressions are not checked here). Full tunnel devices get real answers, because provider rules do not route their traffic. Your block groups block every device as before.

### Data files, limits and refresh { #provider-rules-data }

Categories come from the `Geositeurl` and `Geoipurl` data files that the profile names. KeenProxy downloads them directly (not through a connection), over HTTPS only, following at most three HTTPS redirects (for example from a release download) and never leaving HTTPS, and extracts only the categories the profile references. For downloads and redirects, KeenProxy refuses loopback, private (RFC 1918 and IPv6 ULA), link-local, unspecified and multicast addresses at connect time, including when a hostname resolves to one. A profile is limited to 256 KiB after decoding, each data file to 16 MiB, geosite data to 100,000 domains and geoip data to 200,000 prefixes in total; a file over a limit fails with a fixed message and its rules stay unavailable. Each file has a one-minute download timeout. A profile with only two-letter `geoip:` tags and no geoip file uses the built-in country databases.

Apply spends at most 20 seconds on these downloads and stops 15 seconds before its own deadline; with less than a second left, it skips them. Rules that lack a data file are installed anyway, and the missing files are downloaded again in the background after 1 minute, then 2, 4 and so on up to 1 hour, without refetching the subscription. Data from an unchanged file is reused for up to one week.

The built rules and the profile they came from are saved with the subscription snapshot in the state directory (private, mode 0600) and restored at start before interception begins. For subscriptions that send an HWID, KeenProxy restores cached provider text and rules only when the current installation identity matches the identity used for the fetch. Rules without a match are evaluated again on the next fetch. If the provider withholds rules, you can keep the saved subscription mode. Choosing it from another mode requires a refresh that supplies rules. If a refresh fails after complete rules were built for the same identity, those rules stay in use. A successful attempt replaces incomplete rules. Turning `provider_rules` off frees them.

## Reserve for a subscription { #subscription-reserve }

A subscription can name a reserve with `fallback`: a manual connection ID, `direct` or `block`. For the automatic target, when no node answers for `failover.down_after`, traffic goes to the reserve instead of staying on a dead node. A connection with its own fallback chain keeps that chain while it serves as the reserve. Traffic returns to a node once one has passed its checks for `failover.up_after`. The balancing modes have no such delay: they follow each node's latest check, so they use the reserve as soon as no node's latest check passed (including right after start, before the first check) and return on the first passing check. A pinned node whose node disappeared from the subscription, and a subscription that has no nodes at all, use the reserve directly, without a switch reason. Without a reserve, the automatic target stays on its last node, and balancing, pinned or empty targets block. The subscription status shows the reserve and reports the switch reason `fallback` while it is in use. A subscription cannot be the reserve of another subscription, and connections cannot reference subscriptions.

```yaml
subscriptions:
  - {id: provider, url: "https://provider.example/links/example-token", fallback: home-wg}
```

## Pause and devices that are off { #pause }

A device whose mode is `off` uses the router's ordinary network path and DNS. Turning off **Enabled** on **Overview** (`paused: true`) does the same for every device while the daemon keeps running. Turn it back on to resume. DNS interception and the encrypted-DNS guard apply only to devices that take part in a network or client policy.

```yaml
paused: true
```

## DNS

The `dns` section in YAML chooses upstream resolvers and whether requests travel directly or through a connection. Bootstrap addresses help resolve encrypted resolver hostnames. The failure policy determines whether direct DNS is allowed if the selected path fails.

If a LAN resolver used by KeenProxy forwards requests back through the router on port 53, interception can send them to that same resolver again. Give the resolver a fixed IPv4 address or a DHCP reservation. Add its source IPv4 address to `dns.bypass_sources` in the existing `dns` section, replace the example address, then validate and restart. An empty list uses normal interception. [Edit and reload YAML](user-guide.md#edit-and-reload-yaml)

```yaml
dns:
  bypass_sources: ["192.0.2.53"]
```

The listed sources bypass KeenProxy and its DNS filtering for UDP and TCP port 53 on the configured LAN interface. Other clients, other application ports, and encrypted DNS rules retain their policies. Add only trusted resolvers that require this exception. The router's own forwarding rules still apply.

After restarting, check DNS service state in **Diagnostics**. Test UDP and TCP DNS queries from the resolver and a participating client. Confirm that the resolver can reach its upstream without a loop and the participating client still follows the intended DNS policy. [Troubleshooting](troubleshooting.md)
