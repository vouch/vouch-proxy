package cookie

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	// "github.com/vouch/vouch-proxy/pkg/structs"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
)

var log = cfg.Cfg.Logger

// SetCookie http
func SetCookie(w http.ResponseWriter, r *http.Request, val string) {
	setCookie(w, r, val, cfg.Cfg.Cookie.MaxAge*60) // convert minutes to seconds
}

func setCookie(w http.ResponseWriter, r *http.Request, val string, maxAge int) {
	cookieName := cfg.Cfg.Cookie.Name
	// foreach domain
	domain := domains.Matches(r.Host)
	// Allow overriding the cookie domain in the config file
	if cfg.Cfg.Cookie.Domain != "" {
		domain = cfg.Cfg.Cookie.Domain
		log.Debugf("setting the cookie domain to %v", domain)
	}
	cookie := http.Cookie{
		Name:     cfg.Cfg.Cookie.Name,
		Value:    val,
		Path:     "/",
		Domain:   domain,
		MaxAge:   maxAge,
		Secure:   cfg.Cfg.Cookie.Secure,
		HttpOnly: cfg.Cfg.Cookie.HTTPOnly,
	}
	cookieSize := len(cookie.String())
	cookie.Value = ""
	emptyCookieSize := len(cookie.String())
	// Cookies have a max size of 4096 bytes, but to support most browsers, we should stay below 4000 bytes
	// https://tools.ietf.org/html/rfc6265#section-6.1
	// http://browsercookielimits.squawky.net/
	if cookieSize > 4000 {
		// https://www.lifewire.com/cookie-limit-per-domain-3466809
		log.Warnf("cookie size: %d.  cookie sizes over ~4093 bytes(depending on the browser and platform) have shown to cause issues or simply aren't supported.", cookieSize)
		cookieParts := SplitCookie(val, 4000-emptyCookieSize)
		for i, cookiePart := range cookieParts {
			if i > 0 {
				cookieName = fmt.Sprintf("%s%d", cfg.Cfg.Cookie.Name, i)
			} else {
				cookieName = cfg.Cfg.Cookie.Name
			}
			// Cookies are named with adding 1, 2, 3, etc after the original name per part.
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    cookiePart,
				Path:     "/",
				Domain:   domain,
				MaxAge:   maxAge,
				Secure:   cfg.Cfg.Cookie.Secure,
				HttpOnly: cfg.Cfg.Cookie.HTTPOnly,
			})
		}
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    val,
			Path:     "/",
			Domain:   domain,
			MaxAge:   maxAge,
			Secure:   cfg.Cfg.Cookie.Secure,
			HttpOnly: cfg.Cfg.Cookie.HTTPOnly,
		})
	}
}

// Cookie get the vouch jwt cookie
func Cookie(r *http.Request) (string, error) {
	var err error
	cookies := r.Cookies()
	var combinedCookie strings.Builder
	// Get the remaining parts
	for i := 0; i <= len(cookies); i++ {
		// search for cookie parts in order
		for _, cookie := range cookies {
			// Find the first cookie part
			if i == 0 {
				if cookie.Name == cfg.Cfg.Cookie.Name {
					log.Debugw("cookie",
						"cookieName", cookie.Name,
						"cookieValue", cookie.Value,
					)
					combinedCookie.WriteString(cookie.Value)
					break
				}
			} else {
				// Get the remaining parts
				if cookie.Name == fmt.Sprintf("%s%d", cfg.Cfg.Cookie.Name, i) {
					log.Debugw("cookie",
						"cookieName", cookie.Name,
						"cookieValue", cookie.Value,
					)
					combinedCookie.WriteString(cookie.Value)
					break
				}
			}
		}
	}
	combinedCookieStr := combinedCookie.String()
	if combinedCookieStr == "" {
		return "", errors.New("Cookie token empty")
	}

	log.Debugw("combined cookie",
		"cookieValue", combinedCookieStr,
	)
	return combinedCookieStr, err
}

// ClearCookie get rid of the existing cookie
func ClearCookie(w http.ResponseWriter, r *http.Request) {
	cookies := r.Cookies()
	domain := domains.Matches(r.Host)
	// Allow overriding the cookie domain in the config file
	if cfg.Cfg.Cookie.Domain != "" {
		domain = cfg.Cfg.Cookie.Domain
		log.Debugf("setting the cookie domain to %v", domain)
	}
	// search for cookie parts
	for _, cookie := range cookies {
		if strings.HasPrefix(cookie.Name, cfg.Cfg.Cookie.Name) {
			log.Debugf("deleting cookie: %s", cookie.Name)
			http.SetCookie(w, &http.Cookie{
				Name:     cookie.Name,
				Value:    "delete",
				Path:     "/",
				Domain:   domain,
				MaxAge:   -1,
				Secure:   cfg.Cfg.Cookie.Secure,
				HttpOnly: cfg.Cfg.Cookie.HTTPOnly,
			})
		}
	}
}

func SplitCookie(longString string, maxLen int) []string {
	splits := []string{}

	var l, r int
	for l, r = 0, maxLen; r < len(longString); l, r = r, r+maxLen {
		for !utf8.RuneStart(longString[r]) {
			r--
		}
		splits = append(splits, longString[l:r])
	}
	splits = append(splits, longString[l:])
	return splits
}
