package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

// A configuration larger than the 2 MiB limit of the smaller JSON endpoints,
// but within maxConfigJSONBytes, survives PUT and GET over a loopback connection.
func TestLargeConfigRoundTripsOverLoopback(t *testing.T) {
	s, d := newServer()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	draft := &model.Config{}
	draft.Defaults()
	label := strings.Repeat("x", 36)
	for i := range 2000 {
		group := model.Group{Name: fmt.Sprintf("Group %04d", i), Target: model.TargetDirect}
		for j := range 25 {
			group.Entries = append(group.Entries, fmt.Sprintf("host%02d.group%04d.%s.example", j, i, label))
		}
		draft.Groups = append(draft.Groups, group)
	}
	body, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 2<<20 || len(body) > maxConfigJSONBytes {
		t.Fatalf("fixture outside the large Apply range: %d bytes", len(body))
	}

	call := func(method string, payload []byte) []byte {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+"/api/config", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s /api/config: %d %.200s %v", method, resp.StatusCode, got, err)
		}
		return bytes.TrimSuffix(got, []byte("\n"))
	}
	if got := call(http.MethodPut, body); !bytes.Equal(got, body) {
		t.Fatalf("PUT returned a different configuration: %d bytes, sent %d", len(got), len(body))
	}
	if d.applied == nil || len(d.applied.Groups) != len(draft.Groups) {
		t.Fatal("PUT did not apply every group")
	}
	if got := call(http.MethodGet, nil); !bytes.Equal(got, body) {
		t.Fatalf("GET returned a different configuration: %d bytes, sent %d", len(got), len(body))
	}
}
