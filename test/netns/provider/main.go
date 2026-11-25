// Command provider serves subscriptions with Happ routing profiles over
// HTTPS for integration tests. It writes a self-signed certificate for the
// listen address, which KeenProxy trusts through SSL_CERT_FILE:
//
//	provider [-dat-dir dir] 198.51.100.2:8444 ca.pem nodes.txt profile.json [/path nodes.txt profile.json]...
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
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// main serves the default /sub and any additional fixtures with one certificate.
func main() {
	datDir := flag.String("dat-dir", "", "serve .dat fixtures from this directory at /data/")
	flag.Parse()
	args := flag.Args()
	if len(args) < 4 || (len(args)-4)%3 != 0 {
		log.Fatal("usage: provider [-dat-dir dir] listen cert nodes profile [path nodes profile]...")
	}
	listen, certPath := args[0], args[1]
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	serveSubscription(mux, "/sub", args[2], args[3])
	for i := 4; i < len(args); i += 3 {
		serveSubscription(mux, args[i], args[i+1], args[i+2])
	}
	if *datDir != "" {
		mux.Handle("GET /data/", datHandler(*datDir))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	cert, err := selfSigned(net.ParseIP(host), certPath)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := tls.Listen("tcp", listen, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Fatal(err)
	}
	// Log unserved paths too, so a missing dat file proves an actual HTTPS request.
	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		mux.ServeHTTP(w, r)
	})))
}

// datHandler opens the file for each request so the workload can model a
// missing file becoming available at the same URL before a scheduled retry.
func datHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := strings.CutPrefix(r.URL.Path, "/data/")
		if !ok || filepath.Base(name) != name || !strings.HasSuffix(name, ".dat") {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(dir, name))
	})
}

// serveSubscription freezes the nodes and routing header from fixture files.
func serveSubscription(mux *http.ServeMux, path, nodesPath, profilePath string) {
	nodes, err := os.ReadFile(nodesPath)
	if err != nil {
		log.Fatal(err)
	}
	profile, err := os.ReadFile(profilePath)
	if err != nil {
		log.Fatal(err)
	}
	routing := "happ://routing/add/" + base64.StdEncoding.EncodeToString(profile)
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("routing", routing)
		_, _ = w.Write(nodes)
	})
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
