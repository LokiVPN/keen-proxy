package subscription

import "net/http"

// UseProbeTransport lets tests reach loopback report fixtures; production
// fetchers always use the public-only report transport.
func UseProbeTransport(f *Fetcher, transport http.RoundTripper) { f.probeTransport = transport }
