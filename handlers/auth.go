package handlers

import (
	"fmt"
	"net/http"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

// CallbackHandler /auth
// - validate info from oauth provider (Google, GitHub, OIDC, etc)
// - issue jwt in the form of a cookie
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/auth")
	// Handle the exchange code to initiate a transport.

	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	if err != nil {
		log.Errorf("/auth could not find session store %s", cfg.Cfg.Session.Name)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// is the nonce "state" valid?
	queryState := r.URL.Query().Get("state")
	if session.Values["state"] != queryState {
		log.Errorf("/auth Invalid session state: stored %s, returned %s", session.Values["state"], queryState)
		renderIndex(w, "/auth Invalid session state.")
		return
	}

	errorState := r.URL.Query().Get("error")
	if errorState != "" {
		errorDescription := r.URL.Query().Get("error_description")
		log.Warn("/auth Error state: ", errorState, ", Error description: ", errorDescription)
		w.WriteHeader(http.StatusForbidden)
		renderIndex(w, "FORBIDDEN: "+errorDescription)
		return
	}

	user := structs.User{}
	customClaims := structs.CustomClaims{}
	ptokens := structs.PTokens{}

	if err := getUserInfo(r, &user, &customClaims, &ptokens); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Debugf("/auth Claims from userinfo: %+v", customClaims)
	//getProviderJWT(r, &user)
	log.Debug("/auth CallbackHandler")
	log.Debugf("/auth %+v", user)

	if ok, err := verifyUser(user); !ok {
		log.Error(err)
		renderIndex(w, fmt.Sprintf("/auth User is not authorized. %s Please try again.", err))
		return
	}

	// SUCCESS!! they are authorized

	// issue the jwt
	tokenstring := jwtmanager.CreateUserTokenString(user, customClaims, ptokens)
	cookie.SetCookie(w, r, tokenstring)

	// get the originally requested URL so we can send them on their way
	requestedURL := session.Values["requestedURL"].(string)
	if requestedURL != "" {
		// clear out the session value
		session.Values["requestedURL"] = ""
		session.Values[requestedURL] = 0
		if err = session.Save(r, w); err != nil {
			log.Error(err)
		}

		redirect302(w, r, requestedURL)
		return
	}
	// otherwise serve an html page
	renderIndex(w, "/auth "+tokenstring)
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
			log.Debugf("verifyUser: Success! Email %s found within a "+cfg.Branding.FullName+" managed domain", user.Email)
			return true, nil
		}
		return false, fmt.Errorf("verifyUser: Email %s is not within a "+cfg.Branding.FullName+" managed domain", user.Email)

	// nothing configured, allow everyone through
	default:
		log.Warn("verifyUser: no domains, whitelist, teamWhitelist or AllowAllUsers configured, any successful auth to the IdP authorizes access")
		return true, nil
	}
}

func getUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) error {
	return provider.GetUserInfo(r, user, customClaims, ptokens)
}
