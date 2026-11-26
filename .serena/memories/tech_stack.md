# Dependencies and builds
- See `go.mod` for the module path and Go toolchain requirement. The embedded engine uses pinned sing-box-lx with matching WireGuard/AWG, sing-tun, gVisor and uTLS replacements; dependency-module replacements are not inherited. Engine APIs are version-sensitive. Project license: GPL-3.0-only.
- DNS: miekg/dns; YAML: yaml.v3; Linux policy routing: vishvananda/netlink; MMDB: maxminddb-golang/v2. tools/bench and tools/nlprobe have separate go.mod files.
- Makefile TAGS: with_quic plus PROTO_TAGS (with_utls, with_wireguard, with_awg, with_gvisor, with_xhttp, with_trusttunnel); lite builds use keenproxy_lite plus PROTO_TAGS.
- keenproxy_lite selects internal/engine/registry_lite.go instead of the full registry; size and protocol support depend on build. Lite retains uTLS/WireGuard/AWG/gVisor, omits QUIC.
- UI: server-rendered pages from Go (pending); no ui build tag, embedded frontend or frontend toolchain.
