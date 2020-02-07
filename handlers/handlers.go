package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"

	securerandom "github.com/theckman/go-securerandom"

	"github.com/gorilla/sessions"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/model"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
)

// Index variables passed to index.tmpl
type Index struct {
	Msg      string
	TestURLs []string
	Testing  bool
}

// AuthError sets the values to return to nginx
type AuthError struct {
	Error string
	JWT   string
}

const (
	base64Bytes = 32
)

var (
	// Templates
	indexTemplate = template.Must(template.ParseFiles(filepath.Join(cfg.RootDir, "templates/index.tmpl")))

	// http://www.gorillatoolkit.org/pkg/sessions
	sessstore = sessions.NewCookieStore([]byte(cfg.Cfg.Session.Key))

	log     = cfg.Cfg.Logger
	fastlog = cfg.Cfg.FastLogger
)

func init() {
	sessstore.Options.HttpOnly = cfg.Cfg.Cookie.HTTPOnly
	sessstore.Options.Secure = cfg.Cfg.Cookie.Secure
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
		log.Debugf("looking for redirect URL matching  %v", domain)
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
	// log.Debugf("loginUrl %s", url)
	return lurl
}

// FindJWT look for JWT in Cookie, JWT Header, Authorization Header (OAuth2 Bearer Token)
// and Query String in that order
func FindJWT(r *http.Request) string {
	jwt, err := cookie.Cookie(r)
	if err == nil {
		log.Debugf("jwt from cookie: %s", jwt)
		return jwt
	}
	jwt = r.Header.Get(cfg.Cfg.Headers.JWT)
	if jwt != "" {
		log.Debugf("jwt from header %s: %s", cfg.Cfg.Headers.JWT, jwt)
		return jwt
	}
	auth := r.Header.Get("Authorization")
	if auth != "" {
		s := strings.SplitN(auth, " ", 2)
		if len(s) == 2 {
			jwt = s[1]
			log.Debugf("jwt from authorization header: %s", jwt)
			return jwt
		}
	}
	jwt = r.URL.Query().Get(cfg.Cfg.Headers.QueryString)
	if jwt != "" {
		log.Debugf("jwt from querystring %s: %s", cfg.Cfg.Headers.QueryString, jwt)
		return jwt
	}
	return ""
}

// ClaimsFromJWT parse the jwt and return the claims
func ClaimsFromJWT(jwt string) (jwtmanager.VouchClaims, error) {
	var claims jwtmanager.VouchClaims

	jwtParsed, err := jwtmanager.ParseTokenString(jwt)
	if err != nil {
		// it didn't parse, which means its bad, start over
		log.Error("jwtParsed returned error, clearing cookie")
		return claims, err
	}

	claims, err = jwtmanager.PTokenClaims(jwtParsed)
	if err != nil {
		// claims = jwtmanager.PTokenClaims(jwtParsed)
		// if claims == &jwtmanager.VouchClaims{} {
		return claims, err
	}
	log.Debugf("JWT Claims: %+v", claims)
	return claims, nil
}

// ValidateRequestHandler /validate
// TODO this should use the handler interface
func ValidateRequestHandler(w http.ResponseWriter, r *http.Request) {
	fastlog.Debug("/validate")

	// TODO: collapse all of the `if !cfg.Cfg.PublicAccess` calls
	// perhaps using an `ok=false` pattern
	jwt := FindJWT(r)
	// if jwt != "" {
	if jwt == "" {
		// If the module is configured to allow public access with no authentication, return 200 now
		if cfg.Cfg.PublicAccess {
			w.Header().Add(cfg.Cfg.Headers.User, "")
			log.Debugf("no jwt found, but public access is '%v', returning ok200", cfg.Cfg.PublicAccess)
			ok200(w, r)
		} else {
			error401(w, r, AuthError{Error: "no jwt found in request"})
		}
		return
	}

	claims, err := ClaimsFromJWT(jwt)
	if err != nil {
		// no email in jwt
		if !cfg.Cfg.PublicAccess {
			error401(w, r, AuthError{err.Error(), jwt})
		} else {
			w.Header().Add(cfg.Cfg.Headers.User, "")
		}
		return
	}

	if claims.Username == "" {
		// no email in jwt
		if !cfg.Cfg.PublicAccess {
			error401(w, r, AuthError{"no Username found in jwt", jwt})
		} else {
			w.Header().Add(cfg.Cfg.Headers.User, "")
		}
		return
	}
	fastlog.Info("jwt cookie",
		zap.String("username", claims.Username))

	if !cfg.Cfg.AllowAllUsers {
		if !jwtmanager.SiteInClaims(r.Host, &claims) {
			if !cfg.Cfg.PublicAccess {
				error401(w, r, AuthError{
					fmt.Sprintf("http header 'Host: %s' not authorized for configured `vouch.domains` (is Host being sent properly?)", r.Host),
					jwt})
			} else {
				w.Header().Add(cfg.Cfg.Headers.User, "")
			}
			return
		}
	}
	if len(cfg.Cfg.Headers.Claims) > 0 {
		log.Debug("Found claims in config, finding specific keys...")
		// Run through all the claims found
		for k, v := range claims.CustomClaims {
			// Run through the claims we are looking for
			for _, cv := range cfg.Cfg.Headers.Claims {
				// Check for matching claim
				if cv == k {
					log.Debug("Found matching claim key: ", k)
					customHeader := strings.Join([]string{cfg.Cfg.Headers.ClaimHeader, k}, "")
					// convert to string
					val := fmt.Sprint(v)
					if reflect.TypeOf(val).Kind() == reflect.String {
						// if val, ok := v.(string); ok {
						w.Header().Add(customHeader, val)
						log.Debug("Adding header for claim: ", k, " Name: ", customHeader, " Value: ", val)
					} else if val, ok := v.([]interface{}); ok {
						strs := make([]string, len(val))
						for i, v := range val {
							strs[i] = fmt.Sprintf("\"%s\"", v)
						}
						log.Debug("Adding header for claim: ", k, " Name: ", customHeader, " Value: ", strings.Join(strs, ","))
						w.Header().Add(customHeader, strings.Join(strs, ","))
					} else {
						log.Errorf("Couldn't parse header type for %s %+v.  Please submit an issue.", k, v)
					}
				}
			}
		}
	}

	w.Header().Add(cfg.Cfg.Headers.User, claims.Username)
	w.Header().Add(cfg.Cfg.Headers.Success, "true")

	if cfg.Cfg.Headers.AccessToken != "" {
		if claims.PAccessToken != "" {
			w.Header().Add(cfg.Cfg.Headers.AccessToken, claims.PAccessToken)
		}
	}
	if cfg.Cfg.Headers.IDToken != "" {
		if claims.PIdToken != "" {
			w.Header().Add(cfg.Cfg.Headers.IDToken, claims.PIdToken)

		}
	}
	// fastlog.Debugf("response headers %+v", w.Header())
	// fastlog.Debug("response header",
	// 	zap.String(cfg.Cfg.Headers.User, w.Header().Get(cfg.Cfg.Headers.User)))
	fastlog.Debug("response header",
		zap.Any("all headers", w.Header()))

	// good to go!!
	if cfg.Cfg.Testing {
		renderIndex(w, "user authorized "+claims.Username)
	} else {
		ok200(w, r)
	}

	// TODO
	// parse the jwt and see if the claim is valid for the domain

	// update user last access in a go routine
	// user := structs.User{}
	// err = model.User([]byte(email), &user)
	// if err != nil {
	// 	// no email in jwt, or no email in db
	// 	error401(w, r, err.Error())
	// 	return
	// }
	// if user.Email == "" {
	// 	error401(w, r, "no email found in db")
	// 	return
	// }

	// put the site
	go func() {
		s := structs.Site{Domain: r.Host}
		log.Debugf("site struct: %v", s)
		if err = model.PutSite(s); err != nil {
			log.Error(err)
		}
	}()
}

// LogoutHandler /logout
// currently performs a 302 redirect to Google
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/logout")
	cookie.ClearCookie(w, r)

	log.Debug("saving session")
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
		redirect302(w, r, requestedURL)
	} else {
		renderIndex(w, "/logout you have been logged out")
	}
}

// HealthcheckHandler /healthcheck
// just returns 200 '{ "ok": true }'
func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if _, err := fmt.Fprintf(w, "{ \"ok\": true }"); err != nil {
		log.Error(err)
	}
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

// LoginHandler /login
// currently performs a 302 redirect to Google
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/login")
	// no matter how you ended up here, make sure the cookie gets cleared out
	cookie.ClearCookie(w, r)

	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	if err != nil {
		log.Warnf("couldn't find existing encrypted secure cookie with name %s: %s (probably fine)", cfg.Cfg.Session.Name, err)
	}

	state, err := generateStateNonce()
	if err != nil {
		log.Error(err)
	}

	// set the state variable in the session
	session.Values["state"] = state
	log.Debugf("session state set to %s", session.Values["state"])

	// increment the failure counter for this domain

	// requestedURL comes from nginx in the query string via a 302 redirect
	// it sets the ultimate destination
	// https://vouch.yoursite.com/login?url=
	var requestedURL = r.URL.Query().Get("url")
	if requestedURL == "" {
		renderIndex(w, "/login no destination URL requested")
		log.Error("no destination URL requested")
		return
	}

	// set session variable for eventual 302 redirecton to original request
	session.Values["requestedURL"] = requestedURL
	log.Debugf("session requestedURL set to %s", session.Values["requestedURL"])

	// stop them after three failures for this URL
	var failcount = 0
	if session.Values[requestedURL] != nil {
		failcount = session.Values[requestedURL].(int)
		log.Debugf("failcount for %s is %d", requestedURL, failcount)
	}
	failcount++
	session.Values[requestedURL] = failcount

	log.Debug("saving session")
	if err = session.Save(r, w); err != nil {
		log.Error(err)
	}

	if failcount > 2 {
		var vouchError = r.URL.Query().Get("error")
		renderIndex(w, "/login too many redirects for "+requestedURL+" - "+vouchError)
	} else {
		// bounce to oauth provider for login
		var lURL = loginURL(r, state)
		log.Debugf("redirecting to oauthURL %s", lURL)
		redirect302(w, r, lURL)
	}
}

func renderIndex(w http.ResponseWriter, msg string) {
	if err := indexTemplate.Execute(w, &Index{Msg: msg, TestURLs: cfg.Cfg.TestURLs, Testing: cfg.Cfg.Testing}); err != nil {
		log.Error(err)
	}
}

// VerifyUser validates that the domains match for the user
// func VerifyUser(u structs.User) (ok bool, err error) {
func VerifyUser(u interface{}) (ok bool, err error) {
	// (w http.ResponseWriter, req http.Request)
	// is Hd google specific? probably yes
	// TODO rewrite / abstract this validation
	ok = false

	// TODO: how do we manage the user?
	user := u.(structs.User)

	if cfg.Cfg.AllowAllUsers {
		ok = true
		log.Debugf("skipping verify user since cfg.Cfg.AllowAllUsers is %t", cfg.Cfg.AllowAllUsers)
		// if we're not allowing all users, and we have domains configured and this email isn't in one of those domains...
	} else if len(cfg.Cfg.WhiteList) != 0 {
		for _, wl := range cfg.Cfg.WhiteList {
			if user.Username == wl {
				log.Debugf("found user.Username in WhiteList: %s", user.Username)
				ok = true
				break
			}
		}

		if !ok {
			err = fmt.Errorf("user.Username not found in WhiteList: %s", user.Username)
		}
	} else if len(cfg.Cfg.Domains) != 0 && !domains.IsUnderManagement(user.Email) {
		err = fmt.Errorf("Email %s is not within a "+cfg.Branding.CcName+" managed domain", user.Email)
		// } else if !domains.IsUnderManagement(user.HostDomain) {
		// 	err = fmt.Errorf("HostDomain %s is not within a vouch managed domain", u.HostDomain)
	} else {
		ok = true
		log.Debug("no domains configured")
	}
	return ok, err
}

// CallbackHandler /auth
// - validate info from oauth provider (Google, GitHub, OIDC, etc)
// - create user
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

	if ok, err := VerifyUser(user); !ok {
		log.Error(err)
		renderIndex(w, fmt.Sprintf("/auth User is not authorized. %s Please try again.", err))
		return
	}

	// SUCCESS!! they are authorized

	// store the user in the database
	if err = model.PutUser(user); err != nil {
		log.Error(err)
	}

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

// TODO: put all getUserInfo logic into its own pkg

func getUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) error {

	// indieauth sends the "me" setting in json back to the callback, so just pluck it from the callback
	if cfg.GenOAuth.Provider == cfg.Providers.IndieAuth {
		return getUserInfoFromIndieAuth(r, user, customClaims)
	} else if cfg.GenOAuth.Provider == cfg.Providers.ADFS {
		return getUserInfoFromADFS(r, user, customClaims, ptokens)
	}
	providerToken, err := cfg.OAuthClient.Exchange(context.TODO(), r.URL.Query().Get("code"))
	if err != nil {
		return err
	}
	if cfg.GenOAuth.Provider == cfg.Providers.HomeAssistant {
		ptokens.PAccessToken = providerToken.Extra("access_token").(string)
		return getUserInfoFromHomeAssistant(r, user, customClaims)
	}
	ptokens.PAccessToken = providerToken.AccessToken
	if cfg.GenOAuth.Provider == cfg.Providers.OpenStax {
		client := cfg.OAuthClient.Client(context.TODO(), providerToken)
		return getUserInfoFromOpenStax(client, user, customClaims, providerToken)
	}

	if (providerToken.Extra("id_token") != nil) {
		// Certain providers (eg. gitea) don't provide an id_token
		// and it's not neccessary for the authentication phase
		ptokens.PIdToken = providerToken.Extra("id_token").(string)
	} else {
		log.Debugf("id_token missing - may not be supported by this provider")
	}

	log.Debugf("ptokens: %+v", ptokens)

	// make the "third leg" request back to provider to exchange the token for the userinfo
	client := cfg.OAuthClient.Client(context.TODO(), providerToken)
	if cfg.GenOAuth.Provider == cfg.Providers.Google {
		return getUserInfoFromGoogle(client, user, customClaims)
	} else if cfg.GenOAuth.Provider == cfg.Providers.GitHub {
		return getUserInfoFromGitHub(client, user, customClaims, providerToken)
	} else if cfg.GenOAuth.Provider == cfg.Providers.OIDC {
		return getUserInfoFromOpenID(client, user, customClaims, providerToken)
	}
	log.Error("we don't know how to look up the user info")
	return nil
}

func getUserInfoFromOpenID(client *http.Client, user *structs.User, customClaims *structs.CustomClaims, ptoken *oauth2.Token) (rerr error) {
	userinfo, err := client.Get(cfg.GenOAuth.UserInfoURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("OpenID userinfo body: %s", string(data))
	if err = mapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	if err = json.Unmarshal(data, user); err != nil {
		log.Error(err)
		return err
	}
	user.PrepareUserData()
	return nil
}

func getUserInfoFromOpenStax(client *http.Client, user *structs.User, customClaims *structs.CustomClaims, ptoken *oauth2.Token) (rerr error) {
	userinfo, err := client.Get(cfg.GenOAuth.UserInfoURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("OpenStax userinfo body: %s", string(data))
	if err = mapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	oxUser := structs.OpenStaxUser{}
	if err = json.Unmarshal(data, &oxUser); err != nil {
		log.Error(err)
		return err
	}

	oxUser.PrepareUserData()
	user.Email = oxUser.Email
	user.Name = oxUser.Name
	user.Username = oxUser.Username
	user.ID = oxUser.ID
	user.PrepareUserData()
	return nil
}

func getUserInfoFromGoogle(client *http.Client, user *structs.User, customClaims *structs.CustomClaims) (rerr error) {
	userinfo, err := client.Get(cfg.GenOAuth.UserInfoURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("google userinfo body: %s", string(data))
	if err = mapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	if err = json.Unmarshal(data, user); err != nil {
		log.Error(err)
		return err
	}
	user.PrepareUserData()

	return nil
}

// github
// https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/
func getUserInfoFromGitHub(client *http.Client, user *structs.User, customClaims *structs.CustomClaims, ptoken *oauth2.Token) (rerr error) {

	log.Errorf("ptoken.AccessToken: %s", ptoken.AccessToken)
	userinfo, err := client.Get(cfg.GenOAuth.UserInfoURL + ptoken.AccessToken)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("github userinfo body: %s", string(data))
	if err = mapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	ghUser := structs.GitHubUser{}
	if err = json.Unmarshal(data, &ghUser); err != nil {
		log.Error(err)
		return err
	}
	log.Debug("getUserInfoFromGitHub ghUser")
	log.Debug(ghUser)
	log.Debug("getUserInfoFromGitHub user")
	log.Debug(user)

	ghUser.PrepareUserData()
	user.Email = ghUser.Email
	user.Name = ghUser.Name
	user.Username = ghUser.Username
	user.ID = ghUser.ID
	// user = &ghUser.User

	log.Debug("getUserInfoFromGitHub")
	log.Debug(user)
	return nil
}

func getUserInfoFromIndieAuth(r *http.Request, user *structs.User, customClaims *structs.CustomClaims) (rerr error) {

	code := r.URL.Query().Get("code")
	log.Errorf("ptoken.AccessToken: %s", code)
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	// v.Set("code", code)
	fw, err := w.CreateFormField("code")
	if err != nil {
		return err
	}
	if _, err = fw.Write([]byte(code)); err != nil {
		return err
	}
	// v.Set("redirect_uri", cfg.GenOAuth.RedirectURL)
	if fw, err = w.CreateFormField("redirect_uri"); err != nil {
		return err
	}
	if _, err = fw.Write([]byte(cfg.GenOAuth.RedirectURL)); err != nil {
		return err
	}
	// v.Set("client_id", cfg.GenOAuth.ClientID)
	if fw, err = w.CreateFormField("client_id"); err != nil {
		return err
	}
	if _, err = fw.Write([]byte(cfg.GenOAuth.ClientID)); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		log.Error("error closing writer.")
	}

	req, err := http.NewRequest("POST", cfg.GenOAuth.AuthURL, &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	// v := url.Values{}
	// userinfo, err := client.PostForm(cfg.GenOAuth.UserInfoURL, v)

	client := &http.Client{}
	userinfo, err := client.Do(req)

	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()

	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("indieauth userinfo body: %s", string(data))
	if err = mapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	iaUser := structs.IndieAuthUser{}
	if err = json.Unmarshal(data, &iaUser); err != nil {
		log.Error(err)
		return err
	}
	iaUser.PrepareUserData()
	user.Username = iaUser.Username
	log.Debug(user)
	return nil
}

// More info: https://developers.home-assistant.io/docs/en/auth_api.html
func getUserInfoFromHomeAssistant(r *http.Request, user *structs.User, customClaims *structs.CustomClaims) (rerr error) {
	// Home assistant does not provide an API to query username, so we statically set it to "homeassistant"
	user.Username = "homeassistant"
	return nil
}

type adfsTokenRes struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int64  `json:"expires_in"` // relative seconds from now
}

// More info: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-scenarios-for-developers#supported-scenarios
func getUserInfoFromADFS(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) (rerr error) {
	code := r.URL.Query().Get("code")
	log.Debugf("code: %s", code)

	formData := url.Values{}
	formData.Set("code", code)
	formData.Set("grant_type", "authorization_code")
	formData.Set("resource", cfg.GenOAuth.RedirectURL)
	formData.Set("client_id", cfg.GenOAuth.ClientID)
	formData.Set("redirect_uri", cfg.GenOAuth.RedirectURL)
	if cfg.GenOAuth.ClientSecret != "" {
		formData.Set("client_secret", cfg.GenOAuth.ClientSecret)
	}
	req, err := http.NewRequest("POST", cfg.GenOAuth.TokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(formData.Encode())))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	userinfo, err := client.Do(req)

	if err != nil {
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()

	data, _ := ioutil.ReadAll(userinfo.Body)
	tokenRes := adfsTokenRes{}

	if err := json.Unmarshal(data, &tokenRes); err != nil {
		log.Errorf("oauth2: cannot fetch token: %v", err)
		return nil
	}

	ptokens.PAccessToken = string(tokenRes.AccessToken)
	ptokens.PIdToken = string(tokenRes.IDToken)

	s := strings.Split(tokenRes.IDToken, ".")
	if len(s) < 2 {
		log.Error("jws: invalid token received")
		return nil
	}

	idToken, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		log.Error(err)
		return nil
	}
	log.Debugf("idToken: %+v", string(idToken))

	adfsUser := structs.ADFSUser{}
	json.Unmarshal([]byte(idToken), &adfsUser)
	log.Infof("adfs adfsUser: %+v", adfsUser)
	// data contains an access token, refresh token, and id token
	// Please note that in order for custom claims to work you MUST set allatclaims in ADFS to be passed
	// https://oktotechnologies.ca/2018/08/26/adfs-openidconnect-configuration/
	if err = mapClaims([]byte(idToken), customClaims); err != nil {
		log.Error(err)
		return err
	}
	adfsUser.PrepareUserData()
	var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if len(adfsUser.Email) == 0 {
		// If the email is blank, we will try to determine if the UPN is an email.
		if rxEmail.MatchString(adfsUser.UPN) {
			// Set the email from UPN if there is a valid email present.
			adfsUser.Email = adfsUser.UPN
		}
	}
	user.Username = adfsUser.Username
	user.Email = adfsUser.Email
	log.Debugf("User Obj: %+v", user)
	return nil
}

// the standard error
// this is captured by nginx, which converts the 401 into 302 to the login page
func error401(w http.ResponseWriter, r *http.Request, ae AuthError) {
	log.Error(ae.Error)
	cookie.ClearCookie(w, r)
	// w.Header().Set("X-Vouch-Error", ae.Error)
	http.Error(w, ae.Error, http.StatusUnauthorized)
	// TODO put this back in place if multiple auth mechanism are available
	// c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": errStr})
}

func error401na(w http.ResponseWriter, r *http.Request) {
	error401(w, r, AuthError{Error: "not authorized"})
}

func redirect302(w http.ResponseWriter, r *http.Request, rURL string) {
	if cfg.Cfg.Testing {
		cfg.Cfg.TestURLs = append(cfg.Cfg.TestURLs, rURL)
		renderIndex(w, "302 redirect to: "+rURL)
		return
	}
	http.Redirect(w, r, rURL, http.StatusFound)
}

func ok200(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("200 OK\n"))
	if err != nil {
		log.Error(err)
	}
}

func mapClaims(claims []byte, customClaims *structs.CustomClaims) error {
	// Create a struct that contains the claims that we want to store from the config.
	var f interface{}
	err := json.Unmarshal(claims, &f)
	if err != nil {
		log.Error("Error unmarshaling claims")
		return err
	}
	m := f.(map[string]interface{})
	for k := range m {
		var found = false
		for _, e := range cfg.Cfg.Headers.Claims {
			if k == e {
				found = true
			}
		}
		if found == false {
			delete(m, k)
		}
	}
	customClaims.Claims = m
	return nil
}
