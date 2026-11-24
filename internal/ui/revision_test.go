package ui

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
)

func TestRevisionRejectsStaleForms(t *testing.T) {
	applied := (&model.Config{SchemaVersion: 2}).Clone()
	canonical, err := json.Marshal(applied)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256(canonical))
	revision := Revision(applied)
	if revision != wantHash {
		t.Fatalf("revision %q, want %q", revision, wantHash)
	}
	for _, tc := range []struct {
		name    string
		cfg     *model.Config
		body    string
		matches bool
	}{
		{"current", applied.Clone(), "rev=" + revision, true},
		{"changed in another tab", &model.Config{SchemaVersion: 2, Paused: true}, "rev=" + revision, false},
		{"missing", applied, "", false},
		{"duplicate", applied, "rev=" + revision + "&rev=stale", false},
		{"malformed", applied, "rev=" + revision + "&other=%zz", false},
		{"unavailable config", nil, "rev=" + revision, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/routing", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Accept-Language", "ru-RU")
			p := pages{deps: fakeDeps{config: tc.cfg}}
			cfg, message := p.checkRevision(r)
			if tc.matches {
				if cfg == nil || message != "" {
					t.Fatalf("current revision rejected with %q", message)
				}
				return
			}
			const changed = "\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u0438\u0437\u043c\u0435\u043d\u0438\u043b\u0438\u0441\u044c \u0432 \u0434\u0440\u0443\u0433\u043e\u043c \u043e\u043a\u043d\u0435 \u2014 \u043f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u0438 \u0441\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u0435 \u0435\u0449\u0451 \u0440\u0430\u0437"
			if cfg != nil || message != changed {
				t.Fatalf("unusable revision: config present %v, message %q", cfg != nil, message)
			}
		})
	}
}
