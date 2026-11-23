# Dependencies and builds
- See `go.mod` for the module path and Go toolchain requirement. The embedded engine uses pinned sing-box-lx with matching WireGuard/AWG, sing-tun, gVisor and uTLS replacements; dependency-module replacements are not inherited. Engine APIs are version-sensitive. Project license: GPL-3.0-only.
- DNS: miekg/dns; YAML: yaml.v3; Linux policy routing: vishvananda/netlink; MMDB: maxminddb-golang/v2. tools/bench and tools/nlprobe have separate go.mod files.
- Main Makefile TAGS: with_quic, with_utls, with_wireguard, with_awg, with_gvisor. ui requires web/dist; without ui, web/embed_stub.go permits Go tests without a frontend build.
- keenproxy_lite selects internal/engine/registry_lite.go instead of the full registry; size and protocol support depend on build. Lite retains uTLS/WireGuard/AWG/gVisor, omits QUIC.
- UI: server-rendered pages from Go (pending); no frontend build toolchain.
