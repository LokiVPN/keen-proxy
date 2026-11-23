package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscloseURLUsesConfiguredLocalInterface(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		var v4 []string
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil && ip.To4() != nil {
				v4 = append(v4, ip.String())
			}
		}
		if len(v4) != 1 || v4[0] != "127.0.0.1" {
			continue
		}
		config := filepath.Join(t.TempDir(), "config.yaml")
		writeAccessConfig(t, config, "0.0.0.0:9090", iface.Name)
		var out bytes.Buffer
		if err := discloseAccess(&out, config); err != nil {
			t.Fatal(err)
		}
		if out.String() != "http://127.0.0.1:9090\n" {
			t.Fatalf("wrong local interface URL: %q", out.String())
		}
		return
	}
	t.Skip("requires a loopback interface with only 127.0.0.1 as its IPv4 address")
}

func TestPanelURL(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.8")
	v6 := netip.MustParseAddr("2001:db8::5")
	link4 := netip.MustParseAddr("169.254.1.1")
	zoned := netip.MustParseAddr("fe80::1").WithZone("br0")
	cases := []struct {
		name      string
		listen    string
		iface     string
		addrs     []netip.Addr
		lookupErr error
		want      string
		wantErr   string
		lookup    bool
	}{
		{name: "explicit IPv4", listen: "192.0.2.10:8086", want: "http://192.0.2.10:8086\n"},
		{name: "explicit IPv6 exact", listen: "[2001:DB8:0:0::1]:8086", want: "http://[2001:DB8:0:0::1]:8086\n"},
		{name: "explicit zoned IPv6", listen: "[fe80::1%eth0]:8086", want: "http://[fe80::1%25eth0]:8086\n"},
		{name: "explicit zoned IPv6 space", listen: "[fe80::1%eth 0]:8086", want: "http://[fe80::1%25eth%200]:8086\n"},
		{name: "explicit bad zone", listen: "[fe80::1%bad\nzone]:8086", wantErr: "URL"},
		{name: "explicit port 0", listen: "192.0.2.1:0", wantErr: "port is 0"},
		{
			name: "IPv4 wildcard prefers configured IPv4", listen: "0.0.0.0:9090", iface: "lan0",
			addrs: []netip.Addr{v6, link4, v4}, lookup: true, want: "http://192.0.2.8:9090\n",
		},
		{
			name: "IPv4 wildcard does not choose IPv6", listen: "0.0.0.0:8086", iface: "br0",
			addrs: []netip.Addr{v6}, lookup: true, wantErr: "no IPv4",
		},
		{
			name: "IPv6 wildcard brackets", listen: "[::]:8086", iface: "br0",
			addrs: []netip.Addr{v4, v6}, lookup: true, want: "http://[2001:db8::5]:8086\n",
		},
		{
			name: "IPv6 wildcard does not choose IPv4", listen: "[::]:8086", iface: "br0",
			addrs: []netip.Addr{v4}, lookup: true, wantErr: "no IPv6",
		},
		{
			name: "IPv6 wildcard escapes zone", listen: "[::]:8086", iface: "br0",
			addrs: []netip.Addr{zoned}, lookup: true, want: "http://[fe80::1%25br0]:8086\n",
		},
		{
			name: "IPv6 wildcard adds interface zone", listen: "[::]:8086", iface: "br0",
			addrs: []netip.Addr{netip.MustParseAddr("fe80::1")}, lookup: true, want: "http://[fe80::1%25br0]:8086\n",
		},
		{
			name: "unavailable interface", listen: "0.0.0.0:8086", iface: "missing0",
			lookupErr: errors.New("no such network interface"), lookup: true, wantErr: "missing0",
		},
		{
			name: "no usable address", listen: "0.0.0.0:8086", iface: "br0",
			addrs:  []netip.Addr{netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("224.0.0.1")},
			lookup: true, wantErr: "no IPv4",
		},
		{name: "wildcard port 0", listen: "0.0.0.0:0", iface: "br0", wantErr: "port is 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			lookup := func(name string) ([]netip.Addr, error) {
				called = true
				if name != tc.iface {
					t.Errorf("lookup interface = %q, want %q", name, tc.iface)
				}
				if tc.lookupErr != nil {
					return nil, tc.lookupErr
				}
				return tc.addrs, nil
			}
			var out bytes.Buffer
			err := printPanelURL(&out, tc.listen, tc.iface, lookup)
			if called != tc.lookup {
				t.Errorf("lookup called = %v, want %v", called, tc.lookup)
			}
			if strings.Contains(out.String(), "0.0.0.0") || strings.Contains(out.String(), "[::]") {
				t.Fatalf("stdout invented a wildcard: %q", out.String())
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				if out.Len() != 0 {
					t.Fatalf("stdout = %q", out.String())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("stdout = %q, want %q", out.String(), tc.want)
			}
			parsed, err := url.Parse(strings.TrimSpace(out.String()))
			if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
				t.Fatalf("stdout is not an http URL: %q (%v)", out.String(), err)
			}
		})
	}
}

func TestCLIAccessFlags(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	writeAccessConfig(t, cfg, "192.0.2.9:8086", "br0")
	ruleSets := filepath.Join(dir, "rule-sets")

	t.Run("url", func(t *testing.T) {
		stdout, stderr, code := runKeenproxy(t, "-url", "-config", cfg, "-rule-sets", ruleSets)
		if code != 0 || stderr != "" || stdout != "http://192.0.2.9:8086\n" {
			t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
		}
		assertAbsent(t, filepath.Join(dir, "journal"))
	})
	t.Run("port 0", func(t *testing.T) {
		portCfg := filepath.Join(dir, "port0.yaml")
		writeAccessConfig(t, portCfg, "192.0.2.9:0", "br0")
		stdout, stderr, code := runKeenproxy(t, "-url", "-config", portCfg)
		if code == 0 || stdout != "" || !strings.Contains(stderr, "port is 0") {
			t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
		}
	})
	for _, args := range [][]string{
		{"-url", "-dry-run", "-config", cfg},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runKeenproxy(t, args...)
			if code == 0 || stdout != "" || stderr == "" {
				t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
			}
			if strings.Contains(stdout, "http://") || strings.Contains(stdout, "sing-box") {
				t.Fatalf("conflict disclosed output: %q", stdout)
			}
			assertAbsent(t, filepath.Join(dir, "journal"))
		})
	}
}

// TestKeenproxyMain is the subprocess entry for CLI flag tests. The parent
// process does not set KEENPROXY_RUN_MAIN, so this test is a no-op there.
func TestKeenproxyMain(t *testing.T) {
	if os.Getenv("KEENPROXY_RUN_MAIN") != "1" {
		return
	}
	args := argsAfterDoubleDash(os.Args)
	os.Args = append([]string{"keenproxy"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

func writeAccessConfig(t *testing.T, path, listen, iface string) {
	t.Helper()
	body := fmt.Sprintf("api:\n  listen: %q\nlan:\n  interface: %q\n", listen, iface)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runKeenproxy(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmdArgs := append([]string{"-test.run=^TestKeenproxyMain$", "--"}, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "KEENPROXY_RUN_MAIN=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("timed out; stdout %q stderr %q", stdout.String(), stderr.String())
	}
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), stderr.String(), exitErr.ExitCode()
	}
	t.Fatal(err)
	return "", "", -1
}

func argsAfterDoubleDash(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	return nil
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s exists or could not be checked: %v", path, err)
	}
}
