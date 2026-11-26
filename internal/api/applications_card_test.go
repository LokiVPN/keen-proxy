package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ordo-systems/keen-proxy/internal/model"
	"github.com/ordo-systems/keen-proxy/internal/ui"
)

const applicationsFixture = `<!doctype html><html lang="en"><head>
<script defer src="/applications-card.js"></script>
</head><body><ndw-root><ndw-page-wrapper class="applications">
<ndw-block-header heading="apps.applications"></ndw-block-header>
<div class="applications__container"><div class="applications__column"></div></div>
</ndw-page-wrapper></ndw-root><script>
document.addEventListener("DOMContentLoaded", () => {
    document.querySelector("[data-keenproxy-application-card]")?.click();
});
</script></body></html>`

type cardSetupDeps struct {
	ui.Deps
	cfg *model.Config
}

func (d cardSetupDeps) Config() *model.Config { return d.cfg }

// The browser executes the shipped card and follows its real link. The proxy
// keeps both router names local while preserving their Host headers and ports.
func TestApplicationsCardOpensAuthorizedPages(t *testing.T) {
	browser := os.Getenv("KEENPROXY_TEST_CHROMIUM")
	if browser == "" {
		t.Skip("set KEENPROXY_TEST_CHROMIUM to a Chromium executable")
	}
	script, err := os.ReadFile("../../tools/keenetic-webui/applications-card.js")
	if err != nil {
		t.Fatal(err)
	}
	s, d, _ := keeneticFixture(t)
	opts := ui.Options{
		Role: func(r *http.Request) ui.Role {
			if RoleFrom(r.Context()) == RoleManage {
				return ui.RoleManage
			}
			return ui.RoleDeny
		},
		User:           func(r *http.Request) string { return KeeneticUserFrom(r.Context()) },
		KeeneticOrigin: s.Keenetic.Origin(),
		DirectURL:      s.Keenetic.PanelURL(),
	}
	s.Pages = ui.New(cardSetupDeps{cfg: d.cfg}, opts)
	s.PageError = opts.AccessError
	panel := s.Handler()

	for _, hostname := range []string{"192.168.7.1", "my.keenetic.net"} {
		t.Run(hostname, func(t *testing.T) {
			applicationsHost, panelHost := hostname+":8080", hostname+":8086"
			var openedRoot atomic.Bool
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Host == applicationsHost && r.URL.Path == "/apps":
					http.SetCookie(w, &http.Cookie{Name: routerCookie, Value: routerSession, Path: "/", HttpOnly: true})
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					io.WriteString(w, applicationsFixture)
				case r.Host == applicationsHost && r.URL.Path == "/applications-card.js":
					w.Header().Set("Content-Type", "text/javascript")
					w.Write(script)
				case r.Host == panelHost:
					if r.Method == http.MethodGet && r.URL.Scheme == "http" && r.URL.RequestURI() == "/" {
						openedRoot.Store(true)
					}
					r.RemoteAddr = lan
					panel.ServeHTTP(w, r)
				default:
					http.NotFound(w, r)
				}
			}))
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, browser, "--headless", "--dump-dom", "--disable-background-networking",
				"--no-first-run", "--no-sandbox", "--virtual-time-budget=5000", "--user-data-dir="+t.TempDir(),
				"--proxy-server="+proxy.URL, "--proxy-bypass-list=<-loopback>", "http://"+applicationsHost+"/apps")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("Chromium: %v", err)
			}
			if !openedRoot.Load() {
				t.Errorf("card did not navigate to http://%s/", panelHost)
			}
			dom := string(out)
			if !strings.Contains(dom, `action="/setup/check"`) || !strings.Contains(dom, "operator") {
				t.Fatalf("card did not reach the authenticated setup page: %.1200s", dom)
			}
		})
	}
}
