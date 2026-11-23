package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
)

// ifaceLookup returns addresses configured on a local interface. It must not
// resolve names or open a connection.
type ifaceLookup func(name string) ([]netip.Addr, error)

// discloseAccess prints the configured panel URL. For a file the daemon resets
// at startup it uses the address the reset keeps, and it never changes a file.
// A printed URL is only an address from configuration; it is not a reachability check.
func discloseAccess(w io.Writer, configPath string) error {
	cfg, _, err := loadOrReset(configPath)
	if err != nil {
		return err
	}
	return printPanelURL(w, cfg.API.Listen, cfg.LAN.Interface, interfaceAddrs)
}

// printPanelURL writes one http URL for listen. An explicit host is kept as
// configured, including bracketed IPv6. A wildcard (0.0.0.0 or ::, which also
// accepts IPv4) uses lanAddress, the host KeeneticOS sign-in accepts, and
// never substitutes the wildcard itself.
func printPanelURL(w io.Writer, listen, iface string, lookup ifaceLookup) error {
	raw, err := panelURL(listen, iface, lookup)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, raw)
	return err
}

func panelURL(listen, iface string, lookup ifaceLookup) (string, error) {
	ap, err := netip.ParseAddrPort(listen)
	if err != nil {
		return "", fmt.Errorf("api.listen: %w", err)
	}
	if ap.Port() == 0 {
		return "", errors.New("api.listen: port is 0; bound port is unknown")
	}
	if ap.Addr().IsUnspecified() {
		addr, err := lanAddress(iface, lookup)
		if err != nil {
			return "", err
		}
		return formatHostURL(addr, ap.Port())
	}
	return explicitURL(listen, ap)
}

// lanAddress is the one rule for the router's LAN address: the first private
// IPv4 address of the LAN interface. KeeneticOS sign-in derives its origin
// from it and -url prints it, so -url never names a host that sign-in
// refuses. Without such an address it fails rather than guess.
func lanAddress(iface string, lookup ifaceLookup) (netip.Addr, error) {
	addrs, err := lookup(iface)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("lan interface %s: %w", iface, err)
	}
	for _, addr := range addrs {
		if addr = addr.Unmap(); addr.Is4() && addr.IsPrivate() {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("lan interface %s: no private IPv4 address", iface)
}

func explicitURL(listen string, ap netip.AddrPort) (string, error) {
	if ap.Addr().Zone() == "" {
		raw := "http://" + listen
		if _, err := url.Parse(raw); err != nil {
			return "", fmt.Errorf("api.listen: %w", err)
		}
		return raw, nil
	}
	return formatHostURL(ap.Addr(), ap.Port())
}

// Callers supply a validated address and nonzero port. Keep stdlib URL escaping
// authoritative, including percent-encoded IPv6 zones.
func formatHostURL(addr netip.Addr, port uint16) (string, error) {
	host := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
	raw := (&url.URL{Scheme: "http", Host: host}).String()
	if _, err := url.Parse(raw); err != nil {
		return "", errors.New("api.listen: cannot format URL")
	}
	return raw, nil
}

func interfaceAddrs(name string) ([]netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	raw, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, addr := range raw {
		if ip, ok := addrIP(addr); ok {
			out = append(out, ip)
		}
	}
	return out, nil
}

func addrIP(addr net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return netip.Addr{}, false
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return parsed.Unmap(), true
}
