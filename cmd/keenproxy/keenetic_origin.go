package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
)

// ndmCoreSocket exists only on a KeeneticOS system running NDM.
const ndmCoreSocket = "/var/run/ndm.core.socket"

func isKeenetic() bool {
	_, err := os.Stat(ndmCoreSocket)
	return err == nil
}

// keeneticOrigin chooses the local KeeneticOS HTTP origin for browser sign-in.
// An explicit flag wins and "off" disables sign-in. Otherwise a Keenetic system
// derives the origin from the first private IPv4 of the LAN interface, and any
// other system gets "" (browsers are refused, loopback keeps working). An error
// means Keenetic sign-in is wanted but the address cannot be determined.
func keeneticOrigin(flagValue, lanInterface string, isKeenetic func() bool, addrs func(string) ([]netip.Prefix, error)) (string, error) {
	switch flagValue {
	case "off":
		return "", nil
	case "":
	default:
		return flagValue, nil
	}
	if !isKeenetic() {
		return "", nil
	}
	prefixes, err := addrs(lanInterface)
	if err != nil {
		return "", fmt.Errorf("lan interface %s: %w", lanInterface, err)
	}
	for _, p := range prefixes {
		if a := p.Addr(); a.Is4() && a.IsPrivate() {
			return "http://" + a.String(), nil
		}
	}
	return "", errors.New("lan interface " + lanInterface + ": no private IPv4 address")
}

// interfacePrefixes lists the addresses configured on a local interface.
func interfacePrefixes(name string) ([]netip.Prefix, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	raw, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range raw {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}
