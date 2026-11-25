package ui

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFiles embed.FS

var templates = template.Must(template.New("").Option("missingkey=error").ParseFS(templateFiles, "templates/*.html"))

type pageTab struct {
	Path, Key string
}

var tabs = []pageTab{
	{"/", "nav_overview"},
	{"/routing", "nav_routing"},
	{"/devices", "nav_devices"},
	{"/connections", "nav_connections"},
	{"/diagnostics", "nav_diagnostics"},
}

type pageData struct {
	Lang, Title, Message    string
	User, Origin, DirectURL string
	ActiveTab, Flash        string
	Text                    map[string]string
	Tabs                    []pageTab
	SignedIn, ViewOnly      bool
	Status                  int
	Setup                   *setupPage
	Overview                *overviewPage
	Routing                 *routingPage
	Devices                 *devicesPage
	Connections             *connectionsPage
	ConnectionDetail        *connectionDetailPage
	ConnectionWizard        *connectionWizardPage
	SubscriptionNodes       subscriptionNodesView
	Traffic                 trafficView
	ConnectionHealth        connectionHealthView
	ConnectionHosts         connectionHostsView
	ConnectionTrafficLinks  []connectionReference
}

func (opts Options) pageData(r *http.Request) pageData {
	lang := language(r)
	data := pageData{
		Lang: lang, Text: translations[lang],
		Origin: opts.KeeneticOrigin, DirectURL: opts.DirectURL,
		User: opts.requestUser(r), Tabs: tabs, ActiveTab: r.URL.Path,
	}
	return data
}

func (opts Options) requestUser(r *http.Request) string {
	if opts.User != nil {
		return opts.User(r)
	}
	return ""
}

// AccessError renders screen 1 for a refusal already decided by the server.
func (opts Options) AccessError(w http.ResponseWriter, r *http.Request, status int) {
	data := opts.pageData(r)
	data.Status = status
	switch status {
	case http.StatusUnauthorized:
		data.Title = data.Text["signin_title"]
	case http.StatusServiceUnavailable:
		data.Title = data.Text["unavailable_title"]
	default:
		data.Title = data.Text["denied_title"]
	}
	render(w, r, status, "signin", data)
}

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
}

func render(w http.ResponseWriter, r *http.Request, status int, name string, data pageData) {
	h := w.Header()
	setSecurityHeaders(h)
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Language", data.Lang)
	h.Add("Vary", "Accept-Language")

	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "could not render page", http.StatusInternalServerError)
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = buf.WriteTo(w)
	}
}
