# Overview

![KeenProxy logo](../assets/logo.png){ width="128" style="vertical-align: middle" } &nbsp; ![Ordo Systems](../assets/ordo-systems-logo.png){ width="160" style="vertical-align: middle" }

KeenProxy is an experimental routing application for Keenetic and Netcraze routers with Entware and native OpenWrt routers using procd. It lets you send selected domains, addresses, countries, networks, or devices through a connection, connect directly, or block them. The web interface is the control panel; the router daemon applies the configuration and owns network effects. Firmware and iptables compatibility still require verification on the target router.

## Start here

- **Prepare a router:** read [Getting started](getting-started.md) before installing anything.
- **Learn the workflow:** follow the [user guide](user-guide.md).
- **Understand policy:** read [Routing and DNS](routing.md).
- **Collect evidence:** use [Diagnostics and journal export](troubleshooting.md#download-the-diagnostic-zip) when reporting a router issue.
- **Manage releases:** see [updates and rollback from the panel](getting-started.md#update-from-the-panel).

## The core idea

A **connection** is a named WireGuard, link-based, sing-box, or TrustTunnel profile. A **group** connects domains, addresses, or country selectors to a routing target. **Networks and clients** choose which devices use those rules. **Overview** shows the active connection, and **Diagnostics** shows service state and provides checks and a support report.

Use **Save** on the page where you edited a connection, routing rule, or device setting. **Overview** applies changes to the routing switch and main connection immediately when JavaScript is available. Manage software releases under **Diagnostics → Updates**. [Edit and reload settings such as DNS or country groups](user-guide.md#edit-and-reload-yaml)

!!! warning "Experimental software"
    Compatibility depends on architecture, firmware, kernel capabilities, and build features. Synthetic test results do not prove connectivity, DNS protection, or compatibility with your router.
