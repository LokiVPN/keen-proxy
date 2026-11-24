// Command provider serves a subscription with a Happ routing profile over
// HTTPS for integration tests. It writes a self-signed certificate for the
// listen address, which KeenProxy trusts through SSL_CERT_FILE:
//
//	provider 198.51.100.2:8444 ca.pem nodes.txt profile.json
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

// main serves /sub with the nodes file as the body and the profile as the
// routing header until the test terminates the process.
func main() {
	listen, certPath, nodesPath, profilePath := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		log.Fatal(err)
	}
	nodes, err := os.ReadFile(nodesPath)
	if err != nil {
		log.Fatal(err)
	}
	profile, err := os.ReadFile(profilePath)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := selfSigned(net.ParseIP(host), certPath)
	if err != nil {
		log.Fatal(err)
	}
	routing := "happ://routing/add/" + base64.StdEncoding.EncodeToString(profile)
	http.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		w.Header().Set("routing", routing)
		_, _ = w.Write(nodes)
	})
	ln, err := tls.Listen("tcp", listen, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(ln, nil))
}

// selfSigned creates a certificate for ip and writes it to path as PEM.
func selfSigned(ip net.IP, path string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KeenProxy test provider"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
