package cookie

import (
	"errors"
	"net/http"

	// "github.com/simongottschlag/vouch-proxy/pkg/structs"
	log "github.com/Sirupsen/logrus"
	"github.com/simongottschlag/vouch-proxy/pkg/cfg"
	"github.com/simongottschlag/vouch-proxy/pkg/domains"
	"github.com/spf13/viper"
)

var defaultMaxAge = config.JWT.MaxAge * 60
var config = viper.AllSettings()

// SetCookie http
func SetCookie(w http.ResponseWriter, r *http.Request, val string) {
	setCookie(w, r, val, defaultMaxAge)
}

func setCookie(w http.ResponseWriter, r *http.Request, val string, maxAge int) {
	// foreach domain
	if maxAge == 0 {
		maxAge = defaultMaxAge
	}
	domain := domains.Matches(r.Host)
	// Allow overriding the cookie domain in the config file
	log.Debugf("temp debug - cookie domain: %v", config.Cookie.Domain)
	log.Debugf("temp debug - cookie: %v", config.Cookie)
	log.Debugf("temp debug - cfg: %v", cfg.Cfg)
	log.Debugf("temp debug - host: %v", r.Host)
	log.Debugf("temp debug - cookieConfig: %v", cookieConfig)
	if config.Cookie.Domain != "" {
		domain = config.Cookie.Domain
		log.Debugf("setting the cookie domain to %v", domain)
	}
	// log.Debugf("cookie %s expires %d", config.Cookie.Name, expires)
	http.SetCookie(w, &http.Cookie{
		Name:     config.Cookie.Name,
		Value:    val,
		Path:     "/",
		Domain:   domain,
		MaxAge:   maxAge,
		Secure:   config.Cookie.Secure,
		HttpOnly: config.Cookie.HTTPOnly,
	})
}

// Cookie get the vouch jwt cookie
func Cookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(config.Cookie.Name)
	if err != nil {
		return "", err
	}
	if cookie.Value == "" {
		return "", errors.New("Cookie token empty")
	}

	log.WithFields(log.Fields{
		"cookieName":  config.Cookie.Name,
		"cookieValue": cookie.Value,
	}).Debug("cookie")
	return cookie.Value, err
}

// ClearCookie get rid of the existing cookie
func ClearCookie(w http.ResponseWriter, r *http.Request) {
	setCookie(w, r, "delete", -1)
}
