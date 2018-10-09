package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/LassoProject/lasso/pkg/cfg"
	lctx "github.com/LassoProject/lasso/pkg/context"
	"github.com/LassoProject/lasso/pkg/cookie"
	"github.com/LassoProject/lasso/pkg/domains"
	"github.com/LassoProject/lasso/pkg/jwtmanager"
	"github.com/LassoProject/lasso/pkg/model"
	"github.com/LassoProject/lasso/pkg/structs"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Index variables passed to index.tmpl
type Index struct {
	Msg     string
	TestURL string
}

// AuthError sets the values to return to nginx
type AuthError struct {
	Error string
	JWT   string
}

var (
	genOauth    structs.GenericOauth
	oauthclient *oauth2.Config
	oauthopts   oauth2.AuthCodeOption

	// Templates with functions available to them
	indexTemplate = template.Must(template.ParseFiles("./templates/index.tmpl"))

	sessstore = sessions.NewCookieStore([]byte(cfg.Cfg.Session.Name))
)

func init() {
	log.Debug("init handlers")

	err := cfg.UnmarshalKey("oauth", &genOauth)
	if err == nil {
		if genOauth.Provider == "google" {
			log.Info("configuring google oauth")
			oauthclient = &oauth2.Config{
				ClientID:     genOauth.ClientID,
				ClientSecret: genOauth.ClientSecret,
				Scopes: []string{
					// You have to select a scope from
					// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
					"https://www.googleapis.com/auth/userinfo.email",
				},
				Endpoint: google.Endpoint,
			}
			log.Infof("setting google oauth preferred login domain param 'hd' to %s", genOauth.PreferredDomain)
			oauthopts = oauth2.SetAuthURLParam("hd", genOauth.PreferredDomain)
		} else {
			log.Info("configuring generic oauth")
			oauthclient = &oauth2.Config{
				ClientID:     genOauth.ClientID,
				ClientSecret: genOauth.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  genOauth.AuthURL,
					TokenURL: genOauth.TokenURL,
				},
				RedirectURL: genOauth.RedirectURL,
				Scopes:      genOauth.Scopes,
			}
		}
	}
}

func randString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func loginURL(r *http.Request, state string) string {
	// State can be some kind of random generated hash string.
	// See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12
	var url = ""
	if genOauth.Provider == "google" {
		// If the provider is Google, find a matching redirect URL to use for the client
		domain := domains.Matches(r.Host)
		log.Debugf("looking for redirect URL matching  %v", domain)
		for i, v := range genOauth.RedirectURLs {
			log.Debugf("redirect value matched at [%d]=%v", i, v)
			if strings.Contains(v, domain) {
				oauthclient.RedirectURL = v
				break
			}
		}
		url = oauthclient.AuthCodeURL(state, oauthopts)
	} else {
		url = oauthclient.AuthCodeURL(state)
	}

	// log.Debugf("loginUrl %s", url)
	return url
}

// FindJWT look for JWT in Cookie, JWT Header, Authorization Header (OAuth 2 Bearer Token)
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

// ClaimsFromJWT look everywhere for the JWT, then parse the jwt and return the claims
func ClaimsFromJWT(jwt string) (jwtmanager.LassoClaims, error) {
	// get jwt from cookie.name
	// parse the jwt
	var claims jwtmanager.LassoClaims

	jwtParsed, err := jwtmanager.ParseTokenString(jwt)
	if err != nil {
		// it didn't parse, which means its bad, start over
		log.Error("jwtParsed returned error, clearing cookie")
		return claims, err
	}

	claims, err = jwtmanager.PTokenClaims(jwtParsed)
	if err != nil {
		// claims = jwtmanager.PTokenClaims(jwtParsed)
		// if claims == &jwtmanager.LassoClaims{} {
		return claims, err
	}
	return claims, nil
}

// the standard error
// this is captured by nginx, which converts the 401 into 302 to the login page
func error401(w http.ResponseWriter, r *http.Request, ae AuthError) {
	log.Error(ae.Error)
	cookie.ClearCookie(w, r)
	context.WithValue(r.Context(), lctx.StatusCode, http.StatusUnauthorized)
	// w.Header().Set("X-Lasso-Error", ae.Error)
	http.Error(w, ae.Error, http.StatusUnauthorized)
	// TODO put this back in place if multiple auth mechanism are available
	// c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": errStr})
}

func error401na(w http.ResponseWriter, r *http.Request) {
	error401(w, r, AuthError{Error: "not authorized"})
}

// ValidateRequestHandler /validate
// TODO this should use the handler interface
func ValidateRequestHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/validate")

	jwt := FindJWT(r)
	// if jwt != "" {
	if jwt == "" {
		// If the module is configured to allow public access with no authentication, return 200 now
		if !cfg.Cfg.PublicAccess {
			error401(w, r, AuthError{Error: "no jwt found"})
		} else {
			w.Header().Add("X-Lasso-User", "")
		}
		return
	}

	claims, err := ClaimsFromJWT(jwt)
	if err != nil {
		// no email in jwt
		if !cfg.Cfg.PublicAccess {
			error401(w, r, AuthError{err.Error(), jwt})
		} else {
			w.Header().Add("X-Lasso-User", "")
		}
		return
	}
	if claims.Username == "" {
		// no email in jwt
		if !cfg.Cfg.PublicAccess {
			error401(w, r, AuthError{"no Username found in jwt", jwt})
		} else {
			w.Header().Add("X-Lasso-User", "")
		}
		return
	}
	log.Infof("email from jwt cookie: %s", claims.Username)

	if !cfg.Cfg.AllowAllUsers {
		if !jwtmanager.SiteInClaims(r.Host, &claims) {
			if !cfg.Cfg.PublicAccess {
				error401(w, r, AuthError{"not authorized for " + r.Host, jwt})
			} else {
				w.Header().Add("X-Lasso-User", "")
			}
			return
		}
	}

	// renderIndex(w, "user found from email "+user.Email)
	w.Header().Add("X-Lasso-User", claims.Username)
	w.Header().Add("X-Lasso-Success", "true")
	log.Debugf("X-Lasso-User response headers %s", w.Header().Get("X-Lasso-User"))
	renderIndex(w, "/validate user found in jwt "+claims.Username)

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
		model.PutSite(s)
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
	session.Save(r, w)
	sessstore.MaxAge(300)

	var requestedURL = r.URL.Query().Get("url")
	if requestedURL != "" {
		redirect302(w, r, requestedURL)
	} else {
		renderIndex(w, "/logout you have been logged out")
	}
}

// LoginHandler /login
// currently performs a 302 redirect to Google
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/login")
	// no matter how you ended up here, make sure the cookie gets cleared out
	cookie.ClearCookie(w, r)

	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	if err != nil {
		log.Error(err)
	}

	// set the state variable in the session
	var state = randString()
	session.Values["state"] = state
	log.Debugf("session state set to %s", session.Values["state"])

	// increment the failure counter for this domain

	// requestedURL comes from nginx in the query string via a 302 redirect
	// it sets the ultimate destination
	// https://lasso.yoursite.com/login?url=
	var requestedURL = r.URL.Query().Get("url")
	if requestedURL == "" {
		renderIndex(w, "/login no destination URL requested")
		log.Error("no destination URL requested")
		return
	}

	// set session variable for eventual 302 redirecton to orginal request
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
	session.Save(r, w)

	if failcount > 2 {
		var lassoError = r.URL.Query().Get("error")
		renderIndex(w, "/login too many redirects for "+requestedURL+" - "+lassoError)
	} else {
		// bounce to oauth provider for login
		var lURL = loginURL(r, state)
		log.Debugf("redirecting to oauthURL %s", lURL)
		context.WithValue(r.Context(), lctx.StatusCode, 302)
		redirect302(w, r, lURL)
	}
}

func renderIndex(w http.ResponseWriter, msg string) {
	if err := indexTemplate.Execute(w, &Index{Msg: msg, TestURL: cfg.Cfg.TestURL}); err != nil {
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
	} else if len(cfg.Cfg.Domains) != 0 && !domains.IsUnderManagement(user.Email) {
		err = fmt.Errorf("Email %s is not within a lasso managed domain", user.Email)
		// } else if !domains.IsUnderManagement(user.HostDomain) {
		// 	err = fmt.Errorf("HostDomain %s is not within a lasso managed domain", u.HostDomain)
	} else {
		ok = true
		log.Debug("no domains configured")
	}
	return ok, err
}

// CallbackHandler /auth
// - validate info from oauth provider (Google, Github, OIDC, etc)
// - create user
// - issue jwt in the form of a cookie
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/auth")
	// Handle the exchange code to initiate a transport.

	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	if err != nil {
		log.Errorf("could not find session store %s", cfg.Cfg.Session.Name)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// is the nonce "state" valid?
	queryState := r.URL.Query().Get("state")
	if session.Values["state"] != queryState {
		log.Errorf("Invalid session state: stored %s, returned %s", session.Values["state"], queryState)
		renderIndex(w, "/auth Invalid session state.")
		return
	}

	user := structs.User{}
	if err := getUserInfo(r, &user); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Debug("CallbackHandler")
	log.Debug(user)

	if ok, err := VerifyUser(user); !ok {
		log.Error(err)
		renderIndex(w, fmt.Sprintf("/auth User is not authorized. %s Please try again.", err))
		return
	}

	// SUCCESS!! they are authorized

	// store the user in the database
	model.PutUser(user)

	// issue the jwt
	tokenstring := jwtmanager.CreateUserTokenString(user)
	cookie.SetCookie(w, r, tokenstring)

	// get the originally requested URL so we can send them on their way
	requestedURL := session.Values["requestedURL"].(string)
	if requestedURL != "" {
		// clear out the session value
		session.Values["requestedURL"] = ""
		session.Values[requestedURL] = 0
		session.Save(r, w)

		// and redirect
		context.WithValue(r.Context(), lctx.StatusCode, 302)
		redirect302(w, r, requestedURL)
		return
	}
	// otherwise serve an html page
	renderIndex(w, "/auth "+tokenstring)
}

// TODO: put all getUserInfo logic into its own pkg

func getUserInfo(r *http.Request, user *structs.User) error {

	// indieauth sends the "me" setting in json back to the callback, so just pluck it from the callback
	if genOauth.Provider == "indieauth" {
		return getUserInfoFromIndieAuth(r, user)
	}

	providerToken, err := oauthclient.Exchange(oauth2.NoContext, r.URL.Query().Get("code"))
	if err != nil {
		return err
	}

	// make the "third leg" request back to google to exchange the token for the userinfo
	client := oauthclient.Client(oauth2.NoContext, providerToken)
	if genOauth.Provider == "google" {
		return getUserInfoFromGoogle(client, user)
	} else if genOauth.Provider == "github" {
		return getUserInfoFromGithub(client, user, providerToken)
	} else if genOauth.Provider == "oidc" {
		return getUserInfoFromOpenID(client, user, providerToken)
	}
	log.Error("we don't know how to look up the user info")
	return nil
}

func getUserInfoFromOpenID(client *http.Client, user *structs.User, ptoken *oauth2.Token) error {
	userinfo, err := client.Get(genOauth.UserInfoURL)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer userinfo.Body.Close()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Println("OpenID userinfo body: ", string(data))
	if err = json.Unmarshal(data, user); err != nil {
		log.Errorln(err)
		// renderIndex(w, "Error marshalling response. Please try agian.")
		// c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": })
		return err
	}
	user.PrepareUserData()
	return nil
}

func getUserInfoFromGoogle(client *http.Client, user *structs.User) error {
	userinfo, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer userinfo.Body.Close()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Println("google userinfo body: ", string(data))
	if err = json.Unmarshal(data, user); err != nil {
		log.Errorln(err)
		// renderIndex(w, "Error marshalling response. Please try agian.")
		// c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": })
		return err
	}
	user.PrepareUserData()

	return nil
}

// github
// https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/
func getUserInfoFromGithub(client *http.Client, user *structs.User, ptoken *oauth2.Token) error {

	// TODO: move to cfg package
	userInfoURL := "https://api.github.com/user?access_token="
	if genOauth.UserInfoURL != "" {
		userInfoURL = genOauth.UserInfoURL
	}

	log.Errorf("ptoken.AccessToken: %s", ptoken.AccessToken)
	userinfo, err := client.Get(userInfoURL + ptoken.AccessToken)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer userinfo.Body.Close()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Println("github userinfo body: ", string(data))
	ghUser := structs.GithubUser{}
	if err = json.Unmarshal(data, &ghUser); err != nil {
		log.Errorln(err)
		return err
	}
	log.Debug("getUserInfoFromGithub ghUser")
	log.Debug(ghUser)
	log.Debug("getUserInfoFromGithub user")
	log.Debug(user)

	ghUser.PrepareUserData()
	user.Email = ghUser.Email
	user.Name = ghUser.Name
	user.Username = ghUser.Username
	user.ID = ghUser.ID
	// user = &ghUser.User

	log.Debug("getUserInfoFromGithub")
	log.Debug(user)
	return nil
}

// indieauth
// https://indieauth.com/developers
type indieResponse struct {
	Email string `json:"me"`
}

func getUserInfoFromIndieAuth(r *http.Request, user *structs.User) error {

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
	// v.Set("redirect_uri", genOauth.RedirectURL)
	fw, err = w.CreateFormField("redirect_uri")
	if _, err = fw.Write([]byte(genOauth.RedirectURL)); err != nil {
		return err
	}
	// v.Set("client_id", genOauth.ClientID)
	fw, err = w.CreateFormField("client_id")
	if _, err = fw.Write([]byte(genOauth.ClientID)); err != nil {
		return err
	}
	w.Close()

	req, err := http.NewRequest("POST", genOauth.AuthURL, &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	// v := url.Values{}
	// userinfo, err := client.PostForm(genOauth.UserInfoURL, v)

	client := &http.Client{}
	userinfo, err := client.Do(req)

	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer userinfo.Body.Close()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Println("indieauth userinfo body: ", string(data))
	ir := indieResponse{}
	if err := json.Unmarshal(data, &ir); err != nil {
		log.Errorln(err)
		return err
	}
	user.Email = ir.Email
	log.Debug(user)
	return nil
}

func redirect302(w http.ResponseWriter, r *http.Request, rURL string) {
	if cfg.Cfg.Testing {
		var tmp = cfg.Cfg.TestURL
		cfg.Cfg.TestURL = rURL
		renderIndex(w, "302 redirect to: "+cfg.Cfg.TestURL)
		cfg.Cfg.TestURL = tmp
		return
	}
	http.Redirect(w, r, rURL, 302)
}
