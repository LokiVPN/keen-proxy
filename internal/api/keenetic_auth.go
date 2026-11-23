package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxKeeneticResponse = 32 << 10

// KeeneticAuth checks browser sessions against the router on this host.
// Only the discovered session cookie is sent to the router.
type KeeneticAuth struct {
	router    url.URL
	panelHost string
	client    *http.Client

	cookieMu   sync.Mutex
	cookieName string
	retryAt    time.Time
}

// NewKeeneticAuth opts into the LAN HTTP session protocol. A literal address
// assigned to the router prevents credentials from being forwarded off-device.
func NewKeeneticAuth(rawOrigin, listen string) (*KeeneticAuth, error) {
	if rawOrigin == "" {
		return nil, nil
	}
	origin, err := url.Parse(rawOrigin)
	if err != nil || origin.Scheme != "http" || origin.User != nil ||
		(origin.Path != "" && origin.Path != "/") || origin.ForceQuery ||
		origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("KeeneticOS authentication requires a local HTTP origin")
	}
	address, err := netip.ParseAddr(origin.Hostname())
	if err != nil || !address.Is4() || !address.IsPrivate() || !localAddress(address) {
		return nil, errors.New("KeeneticOS authentication requires an IP address assigned to this router")
	}
	if port := origin.Port(); port != "" && !validPort(port) {
		return nil, errors.New("invalid KeeneticOS HTTP port")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil || !validPort(port) ||
		(host != "" && host != "0.0.0.0" && host != "::" && host != address.String()) {
		return nil, errors.New("KeenProxy must listen on the KeeneticOS LAN address")
	}
	panelHost := address.String()
	if port != "80" {
		panelHost = net.JoinHostPort(panelHost, port)
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: address.AsSlice()}}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, endpoint string) (net.Conn, error) {
				if !localAddress(address) {
					return nil, errors.New("the KeeneticOS address is no longer local")
				}
				return dialer.DialContext(ctx, network, endpoint)
			},
			MaxConnsPerHost:     8,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
		},
	}
	return newKeeneticAuth(origin, panelHost, client), nil
}

func validPort(port string) bool {
	value, err := strconv.Atoi(port)
	return err == nil && value > 0 && value <= 65535 && strconv.Itoa(value) == port
}

func localAddress(want netip.Addr) bool {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, candidate := range addresses {
		prefix, err := netip.ParsePrefix(candidate.String())
		if err == nil && prefix.Addr().Unmap() == want {
			return true
		}
	}
	return false
}

func newKeeneticAuth(origin *url.URL, panelHost string, client *http.Client) *KeeneticAuth {
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	copy.Jar = nil
	return &KeeneticAuth{router: *origin, panelHost: panelHost, client: &copy}
}

func (a *KeeneticAuth) request(ctx context.Context, method, path, user string, cookie *http.Cookie) (*http.Response, error) {
	target := a.router
	target.Path = path
	target.RawPath = ""
	if user != "" {
		target.RawQuery = (url.Values{"name": {user}}).Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), nil)
	if err != nil {
		return nil, err
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return a.client.Do(req)
}

// sessionCookieName learns the per-router cookie name from the anonymous
// challenge. Discovery retries after failure without delaying daemon startup.
func (a *KeeneticAuth) sessionCookieName(ctx context.Context) string {
	a.cookieMu.Lock()
	defer a.cookieMu.Unlock()
	if a.cookieName != "" {
		return a.cookieName
	}
	if time.Now().Before(a.retryAt) {
		return ""
	}
	resp, err := a.request(ctx, http.MethodGet, "/auth", "", nil)
	a.retryAt = time.Now().Add(time.Second)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("X-Ndm-Challenge") == "" ||
		resp.Header.Get("X-Ndm-Realm") == "" {
		return ""
	}
	var name string
	for _, cookie := range resp.Cookies() {
		if cookie.HttpOnly && !cookie.Secure && cookie.Path == "/" {
			if name != "" {
				return ""
			}
			name = cookie.Name
		}
	}
	a.cookieName = name
	return name
}

func (a *KeeneticAuth) browserCookie(r *http.Request) (*http.Cookie, int) {
	if r.Host != a.panelHost || r.TLS != nil {
		return nil, http.StatusForbidden
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		if r.Header.Get("Origin") != "http://"+a.panelHost || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			return nil, http.StatusForbidden
		}
	}
	if r.Header.Get("Cookie") == "" {
		return nil, http.StatusUnauthorized
	}
	name := a.sessionCookieName(r.Context())
	if name == "" {
		return nil, http.StatusServiceUnavailable
	}
	cookies := r.CookiesNamed(name)
	if len(cookies) != 1 || cookies[0].Value == "" || len(cookies[0].Value) > 1024 {
		return nil, http.StatusUnauthorized
	}
	return cookies[0], http.StatusOK
}

func (a *KeeneticAuth) getJSON(ctx context.Context, path, user string, cookie *http.Cookie, destination any) int {
	resp, err := a.request(ctx, http.MethodGet, path, user, cookie)
	if err != nil {
		return http.StatusServiceUnavailable
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return resp.StatusCode
	case http.StatusOK:
	default:
		return http.StatusServiceUnavailable
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return http.StatusServiceUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeeneticResponse+1))
	if err != nil || len(body) > maxKeeneticResponse || json.Unmarshal(body, destination) != nil {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

// Role is the authority an authenticated caller holds over the daemon.
type Role int

const (
	RoleDeny   Role = iota // no access
	RoleView               // read-only access
	RoleManage             // read and write access
)

type roleKey struct{}

// RoleFrom returns the role decided by the access policy for this request;
// a request that never passed it is denied.
func RoleFrom(ctx context.Context) Role {
	role, _ := ctx.Value(roleKey{}).(Role)
	return role
}

// roleFromTags maps KeeneticOS account tags to a role. Administrators carry
// http and cli; read-only and manager accounts may only view.
func roleFromTags(tags []string) Role {
	if !slices.Contains(tags, "http") {
		return RoleDeny
	}
	if slices.Contains(tags, "readonly") || slices.Contains(tags, "manager") {
		return RoleView
	}
	if slices.Contains(tags, "cli") {
		return RoleManage
	}
	return RoleDeny
}

// verify requires the current OS identity and permissions on every request and
// returns the account's role with status 200, or RoleDeny with the refusal
// status. The role is fetched by name instead of loading all users.
func (a *KeeneticAuth) verify(r *http.Request) (Role, int) {
	cookie, status := a.browserCookie(r)
	if status != http.StatusOK {
		return RoleDeny, status
	}
	var identity struct {
		User string `json:"user"`
		Demo bool   `json:"demo-mode"`
	}
	if status := a.getJSON(r.Context(), "/rci/whoami", "", cookie, &identity); status != http.StatusOK {
		return RoleDeny, status
	}
	if identity.Demo || strings.TrimSpace(identity.User) == "" || len(identity.User) > 128 {
		return RoleDeny, http.StatusForbidden
	}
	var users map[string]struct {
		Tag []string `json:"tag"`
	}
	if status := a.getJSON(r.Context(), "/rci/show/sc/user", identity.User, cookie, &users); status != http.StatusOK {
		return RoleDeny, status
	}
	role := roleFromTags(users[identity.User].Tag)
	if len(users) != 1 || role == RoleDeny {
		return RoleDeny, http.StatusForbidden
	}
	return role, http.StatusOK
}

func (a *KeeneticAuth) logout(r *http.Request) int {
	cookie, status := a.browserCookie(r)
	if status == http.StatusUnauthorized {
		return http.StatusOK
	}
	if status != http.StatusOK {
		return status
	}
	resp, err := a.request(r.Context(), http.MethodDelete, "/auth", "", cookie)
	if err != nil {
		return http.StatusServiceUnavailable
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusUnauthorized:
		return http.StatusOK
	default:
		return http.StatusServiceUnavailable
	}
}

func (a *KeeneticAuth) applicationsURL() string {
	return "http://" + a.router.Host + "/apps"
}

// keeneticStatus verifies the browser's KeeneticOS session; no other
// credential grants KeeneticOS authority.
func (s *Server) keeneticStatus(r *http.Request) (Role, int) {
	return s.Keenetic.verify(r)
}

func writeKeeneticError(w http.ResponseWriter, status int) {
	w.Header().Set("X-KeenProxy-Auth", "keenetic")
	switch status {
	case http.StatusUnauthorized:
		writeError(w, status, "KeeneticOS sign-in required")
	case http.StatusForbidden:
		writeError(w, status, "KeeneticOS management access denied")
	default:
		writeError(w, http.StatusServiceUnavailable, "KeeneticOS session check unavailable")
	}
}
