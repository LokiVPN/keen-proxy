// Package subscription reads provider share lists without applying routing policy.
package subscription

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const (
	StateReady        = "ready"
	StateNetworkError = "network_error"
	StateHWIDLimit    = "hwid_limit"
	StateHWIDRequired = "hwid_required"
	StateEmpty        = "empty"
	StateUnsupported  = "unsupported"
	StateInvalid      = "invalid"
	StateHTTPError    = "http_error"
)

// Source is the private configuration of a managed subscription.
type Source struct {
	ID       string `json:"id" yaml:"id"`
	URL      string `json:"url" yaml:"url"`
	SendHWID bool   `json:"send_hwid" yaml:"send_hwid"`
}

// Node contains the original share link for the private snapshot and compiler.
// API handlers must project it to an ID and display name before returning it.
type Node struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Link string `json:"link"`
}

// MatchesLink checks the persisted ID against the link's normalized dial options.
func (n Node) MatchesLink() bool {
	return n.ID != "" && n.ID == nodeID(n.Link)
}

// Metadata carries provider information for display and a bounded refresh hint.
type Metadata struct {
	Title               string `json:"title,omitempty"`
	Announce            string `json:"announce,omitempty"`
	SupportURL          string `json:"support_url,omitempty"`
	ProfileURL          string `json:"profile_url,omitempty"`
	UpdateIntervalHours int    `json:"update_interval_hours,omitempty"`
	Usage               *Usage `json:"usage,omitempty"`
}

// Usage contains byte counts and an expiry expressed in Unix seconds.
type Usage struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

// Result describes one fetch attempt. Its public fields omit private profiles
// and its diagnostic never contains provider-supplied or transport error text.
type Result struct {
	State    string   `json:"state"`
	Metadata Metadata `json:"metadata"`
	Nodes    []Node   `json:"-"`
	Skipped  int      `json:"skipped"`
	Error    string   `json:"error,omitempty"`
	// Transient tells the refresh scheduler to retry with bounded backoff.
	Transient bool `json:"-"`
}

var sourceIDPattern = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// ValidateSource validates a source without resolving the host or opening a connection.
func ValidateSource(source Source) error {
	_, _, err := parseSource(source)
	return err
}

func parseSource(source Source) (*url.URL, string, error) {
	if !sourceIDPattern.MatchString(source.ID) {
		return nil, "", errors.New("subscription ID must use 1 to 64 lowercase letters, digits, underscores or hyphens")
	}
	u, err := url.Parse(source.URL)
	origin := httpsOrigin(u)
	if err != nil || origin == "" || strings.Contains(source.URL, "#") {
		return nil, "", errors.New("subscription URL must be an HTTPS URL without user information or a fragment")
	}
	return u, origin, nil
}

// httpsOrigin normalizes hostname spelling and the effective HTTPS port for the
// redirect check and HWID derivation.
func httpsOrigin(u *url.URL) string {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") {
		return ""
	}
	host := u.Hostname()
	bracketed := strings.HasPrefix(u.Host, "[")
	if address, err := netip.ParseAddr(host); err == nil {
		if bracketed != address.Is6() || address.Zone() != "" {
			return ""
		}
		host = address.String()
	} else {
		ascii, err := idna.Lookup.ToASCII(host)
		if bracketed || err != nil || ascii == "" {
			return ""
		}
		host = strings.ToLower(ascii)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return ""
	}
	return "https://" + net.JoinHostPort(host, strconv.FormatUint(number, 10))
}
