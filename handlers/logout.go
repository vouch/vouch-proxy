package handlers

import (
	"fmt"
	"net/http"

	"github.com/vouch/vouch-proxy/handlers/common"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
)

var errUnauthRedirURL = fmt.Errorf("/logout The requested url is not present in `%s.post_logout_redirect_uris`", cfg.Branding.LCName)

// LogoutHandler /logout
// Destroys Vouch session
// If oauth.logout_url present in conf, also redirects to destroy session at oauth provider
// If "url" param present in request, also redirects to that (after destroying one or both sessions)
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/logout")

	jwt := common.FindJWT(r)
	claims, err := common.ClaimsFromJWT(jwt)
	if err != nil {
		log.Error(err)
	}
		
	token := claims.PIdToken

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

	providerLogoutURL := cfg.GenOAuth.LogoutURL
	redirectURL := r.URL.Query().Get("url")

	// Make sure that redirectURL, if given, is allowed by config
	if redirectURL != "" {
		redirectValid := false
		for _, allowed := range cfg.Cfg.LogoutRedirectURLs {
			if allowed == redirectURL {
				log.Debugf("/logout found ")
				redirectValid = true
				break
			}
		}
		if (!redirectValid) {
			error400(w, r, fmt.Errorf("%w: %s", errUnauthRedirURL, redirectURL))
			return
		}
	}

	// If provider logout URL is configured, redirect to it (and pass redirectURL along)
	// If provider logout URL is not configured, redirect directly to redirectURL
	if providerLogoutURL != "" {
		req, err := http.NewRequest("GET", providerLogoutURL, nil)
		if err != nil {
			log.Error(err)
		}
	
		q := req.URL.Query()
		if redirectURL != "" {
			q.Add("post_logout_redirect_uri", redirectURL)
		}
		if token != "" {
			// Optional in spec, required by some providers (Okta, for example)
			q.Add("id_token_hint", token)
		}
		req.URL.RawQuery = q.Encode()
		redirectURL = req.URL.String()
	}

	if redirectURL != "" {
		redirect302(w, r, redirectURL)
	} else {
		renderIndex(w, "/logout you have been logged out")
	}
}
