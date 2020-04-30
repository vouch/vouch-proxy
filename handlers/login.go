package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/theckman/go-securerandom"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"golang.org/x/oauth2"
)

var errTooManyRedirects = errors.New("too many redirects for requested URL")

// LoginHandler /login
// currently performs a 302 redirect to Google
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/login")
	// no matter how you ended up here, make sure the cookie gets cleared out
	cookie.ClearCookie(w, r)

	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	if err != nil {
		log.Infof("couldn't find existing encrypted secure cookie with name %s: %s (probably fine)", cfg.Cfg.Session.Name, err)
	}

	state, err := generateStateNonce()
	if err != nil {
		log.Error(err)
	}

	// set the state variable in the session
	session.Values["state"] = state
	log.Debugf("session state set to %s", session.Values["state"])

	// requestedURL comes from nginx in the query string via a 302 redirect
	// it sets the ultimate destination
	// https://vouch.yoursite.com/login?url=
	var requestedURL = r.URL.Query().Get("url")
	// need to clean the URL to prevent malicious redirection

	if err := validateRequestedURL(requestedURL); err != nil {
		renderIndex(w, fmt.Sprintf("/login %s", err))
		log.Error(err.Error())
		return
	}

	// set session variable for eventual 302 redirecton to original request
	session.Values["requestedURL"] = requestedURL
	log.Debugf("session requestedURL set to %s", session.Values["requestedURL"])

	// increment the failure counter for the requestedURL
	// stop them after three failures for this URL
	var failcount = 0
	if session.Values[requestedURL] != nil {
		failcount = session.Values[requestedURL].(int)
		log.Debugf("failcount for %s is %d", requestedURL, failcount)
	}
	failcount++
	session.Values[requestedURL] = failcount

	log.Debugf("saving session with failcount %d", failcount)
	if err = session.Save(r, w); err != nil {
		log.Error(err)
	}

	if failcount > 2 {
		var vouchError = r.URL.Query().Get("error")
		renderIndex(w, fmt.Sprintf("/login %s for %s - %s", errTooManyRedirects, requestedURL, vouchError))
		return
	}

	// SUCCESS
	// bounce to oauth provider for login
	var lURL = loginURL(r, state)
	log.Debugf("redirecting to oauthURL %s", lURL)
	redirect302(w, r, lURL)
}

var errNoURL = errors.New("no destination URL requested")
var errInvalidURL = errors.New("requested destination URL appears to be invalid")
var errURLNotHTTP = errors.New("requested destination URL is not a valid URL (does not begin with 'http://' or 'https://')")
var errDangerQS = errors.New("requested destination URL has a dangerous query string")

var badStrings = []string{"http://", "https://", "data:", "ftp://", "ftps://"}

func validateRequestedURL(urlparam string) error {
	if urlparam == "" {
		return errNoURL
	}
	if !strings.HasPrefix(urlparam, "http://") && !strings.HasPrefix(urlparam, "https://") {
		return errURLNotHTTP
	}
	u, err := url.Parse(urlparam)
	if err != nil {
		return fmt.Errorf("won't parse: %w %s", errInvalidURL, err)
	}

	_, err = url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("query string won't parse: %w %s", errInvalidURL, err)
	}

	for k, v := range u.Query() {
		log.Debugf("validateRequestedURL %s:%s", k, v)
		for _, vval := range v {
			for _, bad := range badStrings {
				if strings.HasPrefix(vval, bad) {
					return fmt.Errorf("%w looks bad: %s includes %s", errDangerQS, vval, bad)
				}
			}
		}
	}

	hostname := u.Hostname()
	if cfg.GenOAuth.Provider != cfg.Providers.IndieAuth {
		if domains.Matches(hostname) == "" && !strings.Contains(hostname, cfg.Cfg.Cookie.Domain) {
			return fmt.Errorf("%w: not within a %s managed domain", errInvalidURL, cfg.Branding.FullName)
		}
	}

	return nil
}

func loginURL(r *http.Request, state string) string {
	// State can be some kind of random generated hash string.
	// See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12
	var lurl = ""

	if cfg.GenOAuth.Provider == cfg.Providers.IndieAuth {
		lurl = cfg.OAuthClient.AuthCodeURL(state, oauth2.SetAuthURLParam("response_type", "id"))
	} else if cfg.GenOAuth.Provider == cfg.Providers.ADFS {
		lurl = cfg.OAuthClient.AuthCodeURL(state, cfg.OAuthopts)
	} else {
		domain := domains.Matches(r.Host)
		log.Debugf("looking for callback_url matching  %v", domain)
		for i, v := range cfg.GenOAuth.RedirectURLs {
			if strings.Contains(v, domain) {
				log.Debugf("redirect value matched at [%d]=%v", i, v)
				cfg.OAuthClient.RedirectURL = v
				break
			}
		}
		if cfg.OAuthopts != nil {
			lurl = cfg.OAuthClient.AuthCodeURL(state, cfg.OAuthopts)
		} else {
			lurl = cfg.OAuthClient.AuthCodeURL(state)
		}
	}
	// log.Debugf("loginURL %s", url)
	return lurl
}

var regExJustAlphaNum, _ = regexp.Compile("[^a-zA-Z0-9]+")

func generateStateNonce() (string, error) {
	state, err := securerandom.URLBase64InBytes(base64Bytes)
	if err != nil {
		return "", err
	}
	state = regExJustAlphaNum.ReplaceAllString(state, "")
	return state, nil
}
