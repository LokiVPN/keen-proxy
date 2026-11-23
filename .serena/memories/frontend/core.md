# API and UI
- The Vue panel, Vite demo and Go api.Demo are removed. GET / and any non-/api/ path return 503 "KeenProxy interface is being rebuilt" (api.rebuildingUI, temporary). A server-rendered UI is pending in a later stage; do not reintroduce a SPA build.
- The HTTP API is a control API. A loopback RemoteAddr is trusted without a token and any Authorization header is ignored (installer, memory gate and netns integration use it). Other clients need a KeeneticOS session when KeeneticOS sign-in is enabled (-keenetic-auth-origin); otherwise they get 403 "local access only". Do not trust forwarded headers.
- Removed: panel token, -key, trusted networks, POST /api/login, presets, resource exchange, ad filter lists and panel-only endpoints (GeoIP lookup, domain preview, YAML import/export/previous, DNS check, journal stream/export). api.token_file and api.no_token_from are accepted and ignored.
- Kept for loopback automation: GET/PUT /api/config, /api/status, /api/stats, /api/stats/hosts, GET /api/journal/{kind}, and the support ZIP. Unknown /api/ routes return 404.
- The shared draft/Apply workflow stays the contract for the future UI: one complete config PUT, no separate writes.
