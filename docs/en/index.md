---
title: KeenProxy
hide:
  - navigation
  - toc
---

<div class="kp-landing" markdown>

<section class="kp-hero" markdown>
<div class="kp-hero__text" markdown>

![KeenProxy logo](../assets/logo.png){ .kp-hero__logo width="72" }

# Your network, your routes

Selective traffic routing for Keenetic and Netcraze routers running Entware. Manage connections, device access, and site rules in the browser. Configure advanced policies such as country rules in YAML.

<div class="kp-actions" markdown>
[Get started](getting-started.md){ .md-button .md-button--primary }
</div>

</div>


</section>

<section class="kp-section" markdown>

## What it does

<div class="kp-grid" markdown>

<div class="kp-card" markdown>
:material-devices:{ .kp-card__icon }

### Device and network policies

Split routing, full tunneling, or direct access per network, with per-device overrides by MAC address.
</div>

<div class="kp-card" markdown>
:material-earth:{ .kp-card__icon }

### Domain, IP, and country groups

Route by domain, CIDR, or country — including exclusions such as “everything except Russia”.
</div>

<div class="kp-card" markdown>
:material-vpn:{ .kp-card__icon }

### Many connection types

WireGuard, sing-box connection links, raw sing-box outbounds, and embedded TrustTunnel.
</div>

<div class="kp-card" markdown>
:material-shield-sync:{ .kp-card__icon }

### Failover

Fall back to another connection when one goes down, and return after it has recovered.
</div>

<div class="kp-card" markdown>
:material-dns:{ .kp-card__icon }

### DNS

A local DNS frontend with DoH/DoT resolvers and selectable DNS routing.
</div>

<div class="kp-card" markdown>
:material-file-document-check-outline:{ .kp-card__icon }

### Review and save on each page

Save connection, routing, and device edits on their own pages. **Overview** shows and controls the active connection.
</div>

</div>

</section>

<section class="kp-section" markdown>

## How it works

<div class="kp-steps" markdown>

<div class="kp-step" markdown>
### Add a connection

Import a WireGuard file or a connection link, or use the wizard.
</div>

<div class="kp-step" markdown>
### Choose routing

On **Routing**, follow subscription rules or enter sites and addresses to tunnel or send directly.
</div>

<div class="kp-step" markdown>
### Choose devices

On **Devices**, choose which home devices use KeenProxy and save the page.
</div>

</div>

KeenProxy also watches its interception rules. On compatible Keenetic/Netcraze firmware, a netfilter hook requests a check after firewall changes; a periodic watchdog remains active everywhere, including experimental OpenWrt installations. [How rule recovery works](network-flow.md#how-firewall-rules-recover-after-a-firmware-change).

</section>

<section class="kp-cta" markdown>

## Learn more

<div class="kp-actions" markdown>
[Read the overview](overview.md){ .md-button .md-button--primary }
</div>

<p class="kp-note">KeenProxy is experimental. Compatibility depends on the router architecture, firmware, kernel capabilities, and build features.</p>

</section>

</div>
