package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/compile"
	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

func TestSubscriptionRoutesCarryTrafficThroughFixedAndSelectedNodes(t *testing.T) {
	const source = "provider"
	first := subscriptionTestNode(t, strings.Repeat("a", 32), "first")
	second := subscriptionTestNode(t, strings.Repeat("b", 32), "reserve")
	auto := model.ManagedTarget(source, "auto")
	pinned := model.ManagedTarget(source, first.ID)
	cfg := &model.Config{
		Subscriptions: []subscription.Source{{ID: source, URL: "https://provider.example/sub/list"}},
		Groups: []model.Group{
			{Name: "Auto", Target: auto, Entries: []string{"203.0.113.70"}},
			{Name: "Pinned", Target: pinned, Entries: []string{"203.0.113.71"}},
		},
		Networks: []model.Network{{Name: "Client", CIDR: "127.0.0.1/32", Mode: model.ModeSplit}},
	}
	cfg.Defaults()
	dir := t.TempDir()
	plan, err := compile.Compile(compile.Input{
		Config: cfg, RuleSetDir: dir, Subscriptions: map[string][]subscription.Node{source: {first, second}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range plan.RuleSets {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	autoListener, pinListener := subscriptionTestListener(t), subscriptionTestListener(t)
	autoAddr, pinAddr := autoListener.Addr().(*net.TCPAddr), pinListener.Addr().(*net.TCPAddr)
	autoListener.Close()
	pinListener.Close()
	var runtime map[string]any
	if err := json.Unmarshal(plan.SingBox, &runtime); err != nil {
		t.Fatal(err)
	}
	// Preserve compiled route rules and use a portable client ingress for the test.
	runtime["inbounds"] = []any{
		map[string]any{"type": "direct", "tag": "tcp-in", "listen": "127.0.0.1", "listen_port": autoAddr.Port, "override_address": "203.0.113.70", "override_port": 80},
		map[string]any{"type": "direct", "tag": "pinned-test", "listen": "127.0.0.1", "listen_port": pinAddr.Port, "override_address": "203.0.113.71", "override_port": 80},
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	var core Engine
	t.Cleanup(func() { _ = core.Close() })
	if _, err := core.Apply(raw); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	get := func(host, want string) {
		t.Helper()
		res, err := client.Get("http://" + host + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		got, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != http.StatusOK || string(got) != want {
			t.Fatalf("HTTP through route %q returned %d %q (%v), want %q", host, res.StatusCode, got, err, want)
		}
	}
	if res, err := client.Get("http://" + autoAddr.String() + "/"); err == nil {
		res.Body.Close()
		t.Fatal("auto route allowed traffic before selection")
	}
	if !core.Select(auto, pinned) {
		t.Fatal("could not select first node")
	}
	get(autoAddr.String(), "first")
	if !core.Select(auto, model.ManagedTarget(source, second.ID)) {
		t.Fatal("could not select reserve node")
	}
	get(autoAddr.String(), "reserve")
	get(pinAddr.String(), "first")
}

func subscriptionTestListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

// subscriptionTestNode responds over loopback to the two IPv4 test destinations.
func subscriptionTestNode(t *testing.T, id, marker string) subscription.Node {
	t.Helper()
	listener := subscriptionTestListener(t)
	done := make(chan struct{})
	t.Cleanup(func() { _ = listener.Close(); <-done })
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serveSubscriptionTestNode(conn, marker)
		}
	}()
	return subscription.Node{ID: id, Link: "socks5://" + listener.Addr().String()}
}

func serveSubscriptionTestNode(conn net.Conn, marker string) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting[0] != 5 {
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [10]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil || request[0] != 5 || request[1] != 1 || request[3] != 1 {
		return
	}
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	defer req.Body.Close()
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(marker), marker)
}
