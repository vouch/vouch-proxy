/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gorilla/sessions"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/theckman/go-securerandom"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/responses"
	"golang.org/x/oauth2"
)

// see https://github.com/vouch/vouch-proxy/issues/282
var errTooManyRedirects = errors.New("Too many unsuccessful authorization attempts for the requested URL")

const failCountLimit = 6

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

	// set the path for the session cookie to only send the correct cookie to /auth/{state}/
	// must have a trailing slash. Otherwise, it is send to all endpoints that _start_ with the cookie path.
	session.Options.Path = fmt.Sprintf("%s/auth/%s/", cfg.Cfg.DocumentRoot, state)

	log.Debugf("session state set to %s", session.Values["state"])

	// requestedURL comes from nginx in the query string via a 302 redirect
	// it sets the ultimate destination
	// https://vouch.yoursite.com/login?url=
	// need to clean the URL to prevent malicious redirection
	var requestedURL string
	if requestedURL, err = getValidRequestedURL(r); err != nil {
		responses.Error400(w, r, err)
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

	// Add code challenge if enabled
	if cfg.GenOAuth.CodeChallengeMethod != "" {
		log.Debugf("Adding code challenge")
		appendCodeChallenge(*session)
	}

	log.Debugf("saving session with failcount %d", failcount)
	if err = session.Save(r, w); err != nil {
		log.Error(err)
	}

	if failcount > failCountLimit {
		var vouchError = r.URL.Query().Get("error")
		responses.Error400(w, r, fmt.Errorf("/login %w %s %s", errTooManyRedirects, requestedURL, vouchError))
		return
	}

	// SUCCESS
	// bounce to oauth provider for login
	var oURL = oauthLoginURL(r, *session)
	log.Debugf("redirecting to oauthURL %s", oURL)
	responses.Redirect302(w, r, oURL)
}

var (
	errNoURL      = errors.New("no destination URL requested")
	errInvalidURL = errors.New("requested destination URL appears to be invalid")
	errURLNotHTTP = errors.New("requested destination URL is not a valid URL (does not begin with 'http://' or 'https://')")
	errDangerQS   = errors.New("requested destination URL has a dangerous query string")
	badStrings    = []string{"http://", "https://", "data:", "ftp://", "ftps://", "//", "javascript:"}
	reAmpSemi     = regexp.MustCompile("[&;]")
)

// inspect login query params to located the url param, while taking into account that the login URL may be
// presented in an RFC-non-compliant way (for example, it is common for the url param to
// not have its own query params property encoded, leading to URLs like
// http://host/login?X-Vouch-Token=token&url=http://host/path?param=value&param2=value2&vouch-failcount=value3
// where some params -- here X-Vouch-Token and vouch-failcount -- belong to login, and some others
// -- here param and param2 -- belong to the url param of login)
// The algorithm is as follows:
// * All login params starting with vouch- or x-vouch- (case insensitively) are treated as true login params
// * The "error" login param (case sensitively) is treated as true login param
// * The "rd" login param (case sensitively) added by nginx ingress is treated as true login param https://github.com/vouch/vouch-proxy/issues/289
// * All other login params are treated as non-login params
// * All non-login params between the url param and the first true login param are folded into the url param
// * All remaining non-login params are considered stray non-login params
//
// Returns
// * _, _, err: if an error occurred while parsing the URL
// * URL, empty array, nil: if URL is valid and contains no stray non-login params
// * URL, array of stray params, nil: if URL is valid and contains stray non-login params
func normalizeLoginURLParam(loginURL *url.URL) (*url.URL, []string, error) {
	// url.URL.Query return a map and therefore makes no guarantees about param order
	// Therefore we have to ascertain the param order by inspecting the raw query
	var urlParam *url.URL = nil // Will be url.URL for the url param
	urlParamDone := false       // Will be true when we're done building urlParam (but we're still checking for stray params)
	strays := []string{}        // List of stray params

	for _, param := range reAmpSemi.Split(loginURL.RawQuery, -1) {
		paramKeyVal := strings.Split(param, "=")
		paramKey := paramKeyVal[0]
		lcParamKey := strings.ToLower(paramKey)
		isVouchParam := strings.HasPrefix(lcParamKey, cfg.Branding.LCName) ||
			strings.HasPrefix(lcParamKey, "x-"+cfg.Branding.LCName) ||
			paramKey == "error" || // Used by VouchProxy login
			paramKey == "rd" // Passed to VouchProxy by nginx-ingress and then ignored (see #289)

		if urlParam == nil {
			// Still looking for url param
			if paramKey == "url" {
				// Found it
				parsed, e := url.ParseQuery(param)

				if e != nil {
					return nil, []string{}, e // failure to parse url param
				}

				urlParam, e = url.Parse(parsed.Get("url"))

				if e != nil {
					return nil, []string{}, e // failure to parse url param
				}
			} else if !isVouchParam {
				// Non-vouch param before url param is a stray param
				log.Infof("Stray param in login request (%s)", paramKey)
				strays = append(strays, paramKey)
			} // else vouch param before url param, doesn't change outcome
		} else {
			// Looking at params after url param
			if !urlParamDone && isVouchParam {
				// First vouch param after url param
				urlParamDone = true
				// But keep going to check for strays
			} else if !urlParamDone {
				// Non-vouch param after url and before first vouch param, fold it into urlParam
				if urlParam.RawQuery == "" {
					urlParam.RawQuery = param
				} else {
					urlParam.RawQuery = urlParam.RawQuery + "&" + param
				}
			} else if !isVouchParam {
				// Non-vouch param after vouch param is a stray param
				log.Infof("Stray param in login request (%s)", paramKey)
				strays = append(strays, paramKey)
			} // else vouch param after vouch param, doesn't change outcome
		}
	}

	log.Debugf("Login url param normalized to '%s'", urlParam)
	return urlParam, strays, nil

}

func getValidRequestedURL(r *http.Request) (string, error) {
	u, strays, err := normalizeLoginURLParam(r.URL)

	if len(strays) > 0 {
		log.Debugf("Stray params in login url (%+q) will be ignored", strays)
	}

	if err != nil {
		return "", fmt.Errorf("Not a valid login URL: %w %s", errInvalidURL, err)
	}

	if u == nil || u.String() == "" {
		return "", errNoURL
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errURLNotHTTP
	}

	for _, v := range u.Query() {
		// log.Debugf("validateRequestedURL %s:%s", k, v)
		for _, vval := range v {
			for _, bad := range badStrings {
				if strings.HasPrefix(strings.ToLower(vval), bad) {
					return "", fmt.Errorf("%w looks bad: %s includes %s", errDangerQS, vval, bad)
				}
			}
		}
	}

	hostname := u.Hostname()
	if cfg.GenOAuth.Provider != cfg.Providers.IndieAuth {
		d := domains.Matches(hostname)
		if d == "" {
			inCookieDomain := (hostname == cfg.Cfg.Cookie.Domain || strings.HasSuffix(hostname, "."+cfg.Cfg.Cookie.Domain))
			if cfg.Cfg.Cookie.Domain == "" || !inCookieDomain {
				return "", fmt.Errorf("%w: not within a %s managed domain", errInvalidURL, cfg.Branding.FullName)
			}
		}
	}

	// if the requested URL is http then the cookie cannot be seen if cfg.Cfg.Cookie.Secure is set
	if u.Scheme == "http" && cfg.Cfg.Cookie.Secure {
		return "", fmt.Errorf("%w: mismatch between requested destination URL and '%s.cookie.secure: %v' (the cookie is only visible to 'https' but the requested site is 'http')", errInvalidURL, cfg.Branding.LCName, cfg.Cfg.Cookie.Secure)
	}

	return u.String(), nil
}

func oauthLoginURL(r *http.Request, session sessions.Session) string {
	// State can be some kind of random generated hash string.
	// See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12
	var state string = session.Values["state"].(string)
	opts := []oauth2.AuthCodeOption{}
	if cfg.GenOAuth.Provider == cfg.Providers.IndieAuth {
		return cfg.OAuthClient.AuthCodeURL(state, oauth2.SetAuthURLParam("response_type", "id"))
	}

	// cfg.OAuthClient.RedirectURL is set in cfg
	// this checks the multiple redirect case for multiple matching domains
	if len(cfg.GenOAuth.RedirectURLs) > 0 {
		found := false
		domain := domains.Matches(r.Host)
		log.Debugf("/login looking for callback_url matching %s", domain)
		for _, v := range cfg.GenOAuth.RedirectURLs {
			if strings.Contains(v, domain) {
				found = true
				log.Debugf("/login callback_url set to %s", v)
				cfg.OAuthClient.RedirectURL = v
				break
			}
		}
		if !found {
			log.Infof("/login no callback_url matched %s (is the `Host` header being passed to Vouch Proxy?)", domain)
		}
	}
	// append code challenge and code challenge method query parameters if enabled

	if cfg.GenOAuth.CodeChallengeMethod != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", cfg.GenOAuth.CodeChallengeMethod))
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", session.Values["codeChallenge"].(string)))
	}
	if cfg.OAuthopts != nil {
		opts = append(opts, cfg.OAuthopts...)
	}
	return cfg.OAuthClient.AuthCodeURL(state, opts...)
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

func appendCodeChallenge(session sessions.Session) {
	var codeChallenge string
	var CodeVerifier, _ = cv.CreateCodeVerifier()
	switch strings.ToUpper(cfg.GenOAuth.CodeChallengeMethod) {
	case "S256":
		codeChallenge = CodeVerifier.CodeChallengeS256()
		break
	case "PLAIN":
		codeChallenge = CodeVerifier.CodeChallengePlain()
		// TODO support plain text code challenge
		log.Fatal("plain code challenge method is not supported")
		return
	default:
		log.Fatal("Code challenge method %s is invalid", cfg.GenOAuth.CodeChallengeMethod)
		return
	}
	session.Values["codeChallenge"] = codeChallenge
	session.Values["codeVerifier"] = CodeVerifier.Value
}
