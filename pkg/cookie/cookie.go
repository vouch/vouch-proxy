package cookie

import (
	"errors"
	"net/http"

	// "github.com/vouch/vouch-proxy/pkg/structs"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
)

var log = cfg.Cfg.Logger

// SetCookie http
func SetCookie(w http.ResponseWriter, r *http.Request, val string) {
	setCookie(w, r, val, cfg.Cfg.Cookie.MaxAge)
}

func setCookie(w http.ResponseWriter, r *http.Request, val string, maxAge int) {
	// foreach domain
	domain := domains.Matches(r.Host)
	// Allow overriding the cookie domain in the config file
	if cfg.Cfg.Cookie.Domain != "" {
		domain = cfg.Cfg.Cookie.Domain
		log.Debugf("setting the cookie domain to %v", domain)
	}
	// log.Debugf("cookie %s expires %d", cfg.Cfg.Cookie.Name, expires)
	// Cookies get deleted after the current session (when the browser closes) when no expires or maxage setting is set,
	// or when expires is set to 0.
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.Cfg.Cookie.Name,
			Value:    val,
			Path:     "/",
			Domain:   domain,
			MaxAge:   maxAge,
			Secure:   cfg.Cfg.Cookie.Secure,
			HttpOnly: cfg.Cfg.Cookie.HTTPOnly,
		})
}

// Cookie get the vouch jwt cookie
func Cookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(cfg.Cfg.Cookie.Name)
	if err != nil {
		return "", err
	}
	if cookie.Value == "" {
		return "", errors.New("Cookie token empty")
	}

	log.Debugw("cookie",
		"cookieName", cfg.Cfg.Cookie.Name,
		"cookieValue", cookie.Value,
	)
	return cookie.Value, err
}

// ClearCookie get rid of the existing cookie
func ClearCookie(w http.ResponseWriter, r *http.Request) {
	setCookie(w, r, "delete", -1)
}
