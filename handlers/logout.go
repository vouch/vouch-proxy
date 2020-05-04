package handlers

import (
	"fmt"
	"net/http"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
)

var errUnauthRedirURL = fmt.Errorf("/logout The requested url is not present in `%s.post_logout_redirect_uris`", cfg.Branding.LCName)

// LogoutHandler /logout
// 302 redirect to the provider
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/logout")

	cookie.ClearCookie(w, r)
	log.Debug("/logout deleting session")
	sessstore.MaxAge(-1)
	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	if err != nil {
		log.Error(err)
	}
	if err = session.Save(r, w); err != nil {
		log.Error(err)
	}
	sessstore.MaxAge(300)

	var requestedURL = r.URL.Query().Get("url")
	if requestedURL != "" {
		for _, allowed := range cfg.Cfg.LogoutRedirectURLs {
			if allowed == requestedURL {
				log.Debugf("/logout found ")
				redirect302(w, r, allowed)
				return
			}
		}
		error400(w, r, fmt.Errorf("%w: %s", errUnauthRedirURL, requestedURL))
		return
	}
	renderIndex(w, "/logout you have been logged out")
}
