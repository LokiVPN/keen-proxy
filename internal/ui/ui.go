// Package ui serves the browser interface using daemon-side templates.
package ui

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"time"
)

// Role is the page access granted by the HTTP server.
type Role int

const (
	RoleDeny Role = iota
	RoleView
	RoleManage
)

// Options supplies request identity and the addresses established at startup.
// Role and User read the existing authorization decision without rechecking
// the router session.
type Options struct {
	Role           func(*http.Request) Role
	User           func(*http.Request) string
	KeeneticOrigin string
	DirectURL      string
}

type pages struct {
	deps          Deps
	opts          Options
	setupDrafts   *setupDrafts
	deviceFormKey string
}

// New builds the page handler for the central HTTP server to authorize.
func New(deps Deps, opts Options) http.Handler {
	p := pages{deps: deps, opts: opts, setupDrafts: &setupDrafts{}, deviceFormKey: rand.Text()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.home)
	mux.HandleFunc("POST /overview/pause", p.overviewPause)
	mux.HandleFunc("POST /overview/connection", p.overviewConnection)
	mux.HandleFunc("POST /overview/refresh", p.overviewRefresh)
	mux.HandleFunc("GET /fragments/traffic", p.trafficFragment)
	mux.HandleFunc("GET /setup", p.setupGet)
	mux.HandleFunc("POST /setup/check", p.setupCheck)
	mux.HandleFunc("POST /setup/enable", p.setupEnable)
	mux.HandleFunc("GET /routing", p.routingGet)
	mux.HandleFunc("POST /routing", p.routingPost)
	mux.HandleFunc("GET /devices", p.devicesGet)
	mux.HandleFunc("POST /devices", p.devicesPost)
	mux.HandleFunc("GET /connections", p.connectionsGet)
	mux.HandleFunc("POST /connections", p.connectionsPost)
	mux.HandleFunc("GET /fragments/connections/{source}", p.connectionsFragment)
	mux.HandleFunc("GET /static/", serveAsset)
	mux.HandleFunc("GET /", p.notFound)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (p pages) notFound(w http.ResponseWriter, r *http.Request) {
	for _, tab := range tabs[1:] {
		if r.URL.Path == tab.Path {
			p.renderPage(w, r, http.StatusOK, localized(r)[tab.Key], "section_pending")
			return
		}
	}
	p.renderPage(w, r, http.StatusNotFound, localized(r)["not_found_title"], "not_found_body")
}

func (p pages) renderPage(w http.ResponseWriter, r *http.Request, status int, title, messageKey string) {
	role := p.role(r)
	if role != RoleView && role != RoleManage {
		p.opts.AccessError(w, r, http.StatusForbidden)
		return
	}
	data := p.opts.pageData(r)
	data.Title = title
	data.Message = data.Text[messageKey]
	data.SignedIn = true
	data.ViewOnly = role == RoleView
	data.Flash = takeFlash(w, r, data.Text)
	render(w, r, status, "page", data)
}

func (p pages) role(r *http.Request) Role {
	if p.opts.Role == nil {
		return RoleDeny
	}
	return p.opts.Role(r)
}

//go:embed static/style.css static/app.js static/fonts/*.woff2
var staticFiles embed.FS

type asset struct {
	body []byte
	etag string
}

var assets = loadAssets()

// loadAssets computes validators once for the immutable embedded files.
func loadAssets() map[string]asset {
	out := make(map[string]asset)
	err := fs.WalkDir(staticFiles, "static", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := staticFiles.ReadFile(name)
		if err != nil {
			return err
		}
		out["/"+name] = asset{body: body, etag: fmt.Sprintf("\"%x\"", sha256.Sum256(body))}
		return nil
	})
	if err != nil {
		panic(err)
	}
	return out
}

func serveAsset(w http.ResponseWriter, r *http.Request) {
	name := r.URL.EscapedPath()
	file, ok := assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("ETag", file.etag)
	switch path.Ext(name) {
	case ".css":
		h.Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		h.Set("Content-Type", "text/javascript; charset=utf-8")
	case ".woff2":
		h.Set("Content-Type", "font/woff2")
	}
	http.ServeContent(w, r, path.Base(name), time.Time{}, bytes.NewReader(file.body))
}
