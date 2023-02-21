/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/responses"
)

var errUnauthRedirURL = fmt.Errorf("/logout The requested url is not present in `%s.post_logout_redirect_uris`", cfg.Branding.LCName)

// LogoutHandler /logout
// Destroys Vouch session
// If oauth.end_session_endpoint present in conf, also redirects to destroy session at oauth provider
// If "url" param present in request, also redirects to that (after destroying one or both sessions)
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/logout")

	jwt := jwtmanager.FindJWT(r)
	claims, err := jwtmanager.ClaimsFromJWT(jwt)
	if err != nil {
		log.Error(err)
	}

	var token = ""
	if claims != nil {
		token = claims.PIdToken
	}

	cookie.ClearCookie(w, r)
	log.Debug("/logout deleting session")
	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	session.Options.MaxAge = -1
	if err != nil {
		log.Error(err)
	}
	if err = session.Save(r, w); err != nil {
		log.Error(err)
	}

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
		if !redirectValid {
			responses.Error400(w, r, fmt.Errorf("%w: %s", errUnauthRedirURL, redirectURL))
			return
		}
	}

	// If provider logout URL is configured, redirect to it (and pass redirectURL along)
	// If provider logout URL is not configured, redirect directly to redirectURL
	if providerLogoutURL != "" {
		newRedirectURL, err := url.Parse(providerLogoutURL)
		if err != nil {
			log.Error(err)
		}

		q := newRedirectURL.Query()
		if redirectURL != "" {
			q.Add("post_logout_redirect_uri", redirectURL)
		}
		if token != "" {
			// Optional in spec, required by some providers (Okta, for example)
			q.Add("id_token_hint", token)
		}
		newRedirectURL.RawQuery = q.Encode()
		redirectURL = newRedirectURL.String()
	}

	if redirectURL != "" {
		responses.Redirect302(w, r, redirectURL)
	} else {
		responses.RenderIndex(w, "/logout you have been logged out")
	}
}
