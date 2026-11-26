package ui

import (
	"net/http"
	"strings"
)

const flashCookie = "keenproxy_flash"

// redirectWithFlash carries a fixed message key to the next page in a
// Post/Redirect/Get flow. The cookie never needs to carry user or config data.
func redirectWithFlash(w http.ResponseWriter, r *http.Request, location, key string) {
	if strings.HasPrefix(key, "flash_") && translations["en"][key] != "" {
		setFlashCookie(w, r, key, 60)
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// takeFlash consumes a message only on a page navigation.
func takeFlash(w http.ResponseWriter, r *http.Request, text map[string]string) string {
	if r.Method != http.MethodGet {
		return ""
	}
	cookie, err := r.Cookie(flashCookie)
	if err != nil {
		return ""
	}
	setFlashCookie(w, r, "", -1)
	if !strings.HasPrefix(cookie.Value, "flash_") {
		return ""
	}
	return text[cookie.Value]
}

func setFlashCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: flashCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
}
