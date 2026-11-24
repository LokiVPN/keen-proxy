package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/subscription"
)

type fakeDeps struct {
	Deps
	config *model.Config
}

func (d fakeDeps) Config() *model.Config { return d.config }

func TestLayoutLocales(t *testing.T) {
	opts := Options{
		Role:           func(*http.Request) Role { return RoleView },
		User:           func(*http.Request) string { return "operator <b>view</b>" },
		KeeneticOrigin: "http://192.0.2.1",
		DirectURL:      "http://192.0.2.1:8086",
	}
	cfg := &model.Config{Subscriptions: []subscription.Source{{ID: "sample", URL: "https://provider.example/list"}}}
	h := New(fakeDeps{config: cfg}, opts)
	for _, tc := range []struct {
		acceptLanguage, lang string
		tabs                 []string
		logout, viewOnly     string
	}{
		{"en-US,ru;q=0.8", "en", []string{"Overview", "Routing", "Devices", "Connections", "Diagnostics"}, "Sign out", "View only"},
		{"ru-RU,en;q=0.8", "ru", []string{"\u041e\u0431\u0437\u043e\u0440", "\u041c\u0430\u0440\u0448\u0440\u0443\u0442\u0438\u0437\u0430\u0446\u0438\u044f", "\u0423\u0441\u0442\u0440\u043e\u0439\u0441\u0442\u0432\u0430", "\u041f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f", "\u0414\u0438\u0430\u0433\u043d\u043e\u0441\u0442\u0438\u043a\u0430"}, "\u0412\u044b\u0439\u0442\u0438", "\u0422\u043e\u043b\u044c\u043a\u043e \u043f\u0440\u043e\u0441\u043c\u043e\u0442\u0440"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept-Language", tc.acceptLanguage)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("GET /: HTTP %d, want 200", w.Code)
			}
			assertPageHeaders(t, w.Result(), tc.lang)
			body := w.Body.String()
			assertContains(t, body, "<h1>KeenProxy</h1>", `href="http://192.0.2.1"`, "operator &lt;b&gt;view&lt;/b&gt;",
				`lang="`+tc.lang+`"`, `method="post" action="/api/logout"`, tc.logout, tc.viewOnly)
			paths := []string{"/", "/routing", "/devices", "/connections", "/diagnostics"}
			for i, tab := range tc.tabs {
				assertContains(t, body, `href="`+paths[i]+`"`, ">"+tab+"</a>")
			}
			if strings.Contains(body, "operator <b>") || strings.Contains(body, "style=") {
				t.Fatalf("unexpected inline markup in layout:\n%s", body)
			}
		})
	}
}

func TestScreenOne(t *testing.T) {
	opts := Options{
		User:           func(*http.Request) string { return "guest" },
		KeeneticOrigin: "http://192.0.2.1",
		DirectURL:      "http://192.0.2.1:8086",
	}
	for _, tc := range []struct {
		status  int
		heading string
		details []string
	}{
		{http.StatusUnauthorized, "\u0412\u043e\u0439\u0434\u0438\u0442\u0435 \u0432 \u0440\u043e\u0443\u0442\u0435\u0440", []string{`href="http://192.0.2.1"`, `href="http://192.0.2.1:8086"`}},
		{http.StatusForbidden, "\u041d\u0435\u0442 \u0434\u043e\u0441\u0442\u0443\u043f\u0430", []string{"guest"}},
		{http.StatusServiceUnavailable, "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0441\u0435\u0430\u043d\u0441\u0430 KeeneticOS \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u0430", []string{"SSH"}},
	} {
		r := httptest.NewRequest(http.MethodGet, "/routing", nil)
		r.Header.Set("Accept-Language", "ru")
		w := httptest.NewRecorder()
		opts.AccessError(w, r, tc.status)
		if w.Code != tc.status {
			t.Fatalf("sign-in screen: HTTP %d, want %d", w.Code, tc.status)
		}
		assertPageHeaders(t, w.Result(), "ru")
		body := w.Body.String()
		assertContains(t, body, "<h1>"+tc.heading+"</h1>")
		assertContains(t, body, tc.details...)
		if strings.Contains(body, `action="/api/logout"`) || strings.Contains(body, "style=") {
			t.Fatalf("unexpected controls or inline styles in HTTP %d screen", w.Code)
		}
	}
}

func TestEmbeddedStaticHeaders(t *testing.T) {
	h := New(fakeDeps{}, Options{})
	for _, tc := range []struct{ path, media string }{
		{"/static/style.css", "text/css"},
		{"/static/app.js", "text/javascript"},
		{"/static/fonts/roboto-latin-400-normal.woff2", "font/woff2"},
		{"/static/fonts/roboto-cyrillic-500-normal.woff2", "font/woff2"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			etag := w.Header().Get("ETag")
			if w.Code != http.StatusOK || w.Body.Len() == 0 || etag == "" ||
				!strings.HasPrefix(w.Header().Get("Content-Type"), tc.media) ||
				!strings.Contains(w.Header().Get("Cache-Control"), "max-age=") {
				t.Fatalf("static response HTTP %d, headers %v, size %d", w.Code, w.Header(), w.Body.Len())
			}
			assertSecurityHeaders(t, w.Result())
			if tc.path == "/static/app.js" && w.Body.Len() >= 6<<10 {
				t.Fatalf("app.js takes %d bytes, must be under 6 KiB", w.Body.Len())
			}
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.Header.Set("If-None-Match", etag)
			cached := httptest.NewRecorder()
			h.ServeHTTP(cached, r)
			if cached.Code != http.StatusNotModified || cached.Body.Len() != 0 {
				t.Fatalf("asset with current ETag: HTTP %d, size %d", cached.Code, cached.Body.Len())
			}
		})
	}
}

func assertPageHeaders(t *testing.T, resp *http.Response, lang string) {
	t.Helper()
	assertSecurityHeaders(t, resp)
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") ||
		resp.Header.Get("Cache-Control") != "no-store" ||
		resp.Header.Get("Content-Language") != lang {
		t.Errorf("page headers: %v", resp.Header)
	}
}

func assertSecurityHeaders(t *testing.T, resp *http.Response) {
	t.Helper()
	for name, want := range map[string]string{
		"Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "same-origin",
	} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("%s was %q, want %q", name, got, want)
		}
	}
}

func assertContains(t *testing.T, body string, snippets ...string) {
	t.Helper()
	for _, snippet := range snippets {
		if !strings.Contains(body, snippet) {
			t.Errorf("missing %q from rendered markup:\n%s", snippet, body)
		}
	}
}
