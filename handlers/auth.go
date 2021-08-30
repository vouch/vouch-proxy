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

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/responses"
	"github.com/vouch/vouch-proxy/pkg/structs"

	"golang.org/x/oauth2"
)

// CallbackHandler /auth
// - redirects to /auth/{state}/ with the state coming from the query parameter
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/auth")

	// did the IdP return an error?
	errorIDP := r.URL.Query().Get("error")
	if errorIDP != "" {
		errorDescription := r.URL.Query().Get("error_description")
		responses.Error401HTTP(w, r, fmt.Errorf("/auth Error from IdP: %s - %s", errorIDP, errorDescription))
		return
	}

	queryState := r.URL.Query().Get("state")
	if queryState == "" {
		responses.Error400(w, r, fmt.Errorf("/auth: could not find state in query %s", r.URL.RawQuery))
		return
	}

	// has to have a trailing / in its path, because the path of the session cookie is set to /auth/{state}/.
	// see note in login.go and https://github.com/vouch/vouch-proxy/issues/373
	authStateURL := fmt.Sprintf("%s/auth/%s/?%s", cfg.Cfg.DocumentRoot, queryState, r.URL.RawQuery)
	responses.Redirect302(w, r, authStateURL)
}

// AuthStateHandler /auth/{state}/
// - validate info from oauth provider (Google, GitHub, OIDC, etc)
// - issue jwt in the form of a cookie
func AuthStateHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/auth/{state}/")
	// Handle the exchange code to initiate a transport.

	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	if err != nil {
		responses.Error400(w, r, fmt.Errorf("/auth %w: could not find session store %s", err, cfg.Cfg.Session.Name))
		return
	}

	// is the nonce "state" valid?
	queryState := r.URL.Query().Get("state")
	if session.Values["state"] != queryState {
		responses.Error400(w, r, fmt.Errorf("/auth Invalid session state: stored %s, returned %s", session.Values["state"], queryState))
		return
	}

	user := structs.User{}
	customClaims := structs.CustomClaims{}
	ptokens := structs.PTokens{}

	// is code challenge enabled?
	authCodeOptions := []oauth2.AuthCodeOption{}

	if cfg.GenOAuth.CodeChallengeMethod != "" {
		authCodeOptions = []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("code_challenge", session.Values["codeChallenge"].(string)),
			oauth2.SetAuthURLParam("code_verifier", session.Values["codeVerifier"].(string)),
		}
	}

	if err := getUserInfo(r, &user, &customClaims, &ptokens, authCodeOptions...); err != nil {
		responses.Error400(w, r, fmt.Errorf("/auth Error while retrieving user info after successful login at the OAuth provider: %w", err))
		return
	}
	log.Debugf("/auth/{state}/ Claims from userinfo: %+v", customClaims)

	// verify / authz the user
	if ok, err := verifyUser(user); !ok {
		responses.Error403(w, r, fmt.Errorf("/auth User is not authorized: %w . Please try again or seek support from your administrator", err))
		return
	}

	// SUCCESS!! they are authorized

	// issue the jwt

	tokenstring, err := jwtmanager.NewVPJWT(user, customClaims, ptokens)
	if err != nil {
		responses.Error500(w, r, fmt.Errorf("/auth Token creation failure: %w . Please seek support from your administrator", err))
		return

	}
	cookie.SetCookie(w, r, tokenstring)

	// get the originally requested URL so we can send them on their way
	requestedURL := session.Values["requestedURL"].(string)
	if requestedURL != "" {
		// clear out the session value
		session.Values["requestedURL"] = ""
		session.Values[requestedURL] = 0
		session.Options.MaxAge = -1
		if err = session.Save(r, w); err != nil {
			log.Error(err)
		}

		responses.Redirect302(w, r, requestedURL)
		return
	}

	// otherwise serve an error
	responses.RenderIndex(w, "/auth "+tokenstring)
}

// verifyUser validates that the domains match for the user
func verifyUser(u interface{}) (bool, error) {

	user := u.(structs.User)

	switch {

	// AllowAllUsers
	case cfg.Cfg.AllowAllUsers:
		log.Debugf("verifyUser: Success! skipping verification, cfg.Cfg.AllowAllUsers is %t", cfg.Cfg.AllowAllUsers)
		return true, nil

	// WhiteList
	case len(cfg.Cfg.WhiteList) != 0:
		for _, wl := range cfg.Cfg.WhiteList {
			if user.Username == wl {
				log.Debugf("verifyUser: Success! found user.Username in WhiteList: %s", user.Username)
				return true, nil
			}
		}
		return false, fmt.Errorf("verifyUser: user.Username not found in WhiteList: %s", user.Username)

	// TeamWhiteList
	case len(cfg.Cfg.TeamWhiteList) != 0:
		for _, team := range user.TeamMemberships {
			for _, wl := range cfg.Cfg.TeamWhiteList {
				if team == wl {
					log.Debugf("verifyUser: Success! found user.TeamWhiteList in TeamWhiteList: %s for user %s", wl, user.Username)
					return true, nil
				}
			}
		}
		return false, fmt.Errorf("verifyUser: user.TeamMemberships %s not found in TeamWhiteList: %s for user %s", user.TeamMemberships, cfg.Cfg.TeamWhiteList, user.Username)

	// Domains
	case len(cfg.Cfg.Domains) != 0:
		if domains.IsUnderManagement(user.Email) {
			log.Debugf("verifyUser: Success! Email %s found within a %s managed domain", user.Email, cfg.Branding.FullName)
			return true, nil
		}
		return false, fmt.Errorf("verifyUser: Email %s is not within a %s managed domain", user.Email, cfg.Branding.FullName)

	// nothing configured, allow everyone through
	default:
		log.Warn("verifyUser: no domains, whitelist, teamWhitelist or AllowAllUsers configured, any successful auth to the IdP authorizes access")
		return true, nil
	}
}

func getUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens, opts ...oauth2.AuthCodeOption) error {
	return provider.GetUserInfo(r, user, customClaims, ptokens, opts...)
}
