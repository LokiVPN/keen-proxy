package main

import "os"

// ndmCoreSocket exists only on a KeeneticOS system running NDM.
const ndmCoreSocket = "/var/run/ndm.core.socket"

func isKeenetic() bool {
	_, err := os.Stat(ndmCoreSocket)
	return err == nil
}

// keeneticOrigin chooses the local KeeneticOS HTTP origin for browser sign-in.
// An explicit flag wins and "off" disables sign-in. Otherwise a Keenetic system
// derives the origin from lanAddress, the address -url prints, and any other
// system gets "" (browsers are refused, loopback keeps working). An error
// means Keenetic sign-in is wanted but the address cannot be determined.
func keeneticOrigin(flagValue, lanInterface string, isKeenetic func() bool, lookup ifaceLookup) (string, error) {
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
	addr, err := lanAddress(lanInterface, lookup)
	if err != nil {
		return "", err
	}
	return "http://" + addr.String(), nil
}
