package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/bnfinet/lasso/pkg/cfg"
	lctx "github.com/bnfinet/lasso/pkg/context"
	"github.com/bnfinet/lasso/pkg/cookie"
	"github.com/bnfinet/lasso/pkg/domains"
	"github.com/bnfinet/lasso/pkg/jwtmanager"
	"github.com/bnfinet/lasso/pkg/model"
	"github.com/bnfinet/lasso/pkg/structs"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Index variables passed to index.tmpl
type Index struct {
	Msg string
}

// AuthError sets the values to return to nginx
type AuthError struct {
	Error string
	JWT   string
}

var (
	gcred       structs.GCredentials
	oauthclient *oauth2.Config
	oauthopts   oauth2.AuthCodeOption

	// Templates with functions available to them
	indexTemplate = template.Must(template.ParseFiles("./templates/index.tmpl"))

	sessstore = sessions.NewCookieStore([]byte(cfg.Cfg.Session.Name))
)

func init() {
	log.Debug("init handlers")
	cfg.UnmarshalKey("google", &gcred)

	oauthclient = &oauth2.Config{
		ClientID:     gcred.ClientID,
		ClientSecret: gcred.ClientSecret,
		// RedirectURL:  gcred.RedirectURL,
		Scopes: []string{
			// You have to select a scope from
			// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	log.Infof("setting oauth prefered login domain param 'hd' to %s", cfg.Cfg.PreferredDomain)
	oauthopts = oauth2.SetAuthURLParam("hd", cfg.Cfg.PreferredDomain)
}

func randString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func loginURL(r *http.Request, state string) string {
	// State can be some kind of random generated hash string.
	// See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12

	domain := domains.Matches(r.Host)
	for i, v := range gcred.RedirectURLs {
		log.Debugf("array value at [%d]=%v", i, v)
		if strings.Contains(v, domain) {
			oauthclient.RedirectURL = v
			break
		}
	}

	var url = oauthclient.AuthCodeURL(state, oauthopts)
	// log.Debugf("loginUrl %s", url)
	return url
}

// FindJWT look for JWT in Cookie, Header and Query String in that order
func FindJWT(r *http.Request) string {
	jwt, err := cookie.Cookie(r)
	if err != nil {
		log.Error(err)
		// return ""
	}
	log.Debugf("jwtCookie from cookie: %s", jwt)
	if jwt == "" {
		jwt = r.Header.Get(cfg.Cfg.Headers.SSO)
		log.Debugf("jwtCookie from header %s: %s", cfg.Cfg.Headers.SSO, jwt)
	}
	if jwt == "" {
		jwt = r.URL.Query().Get(cfg.Cfg.Headers.SSO)
		log.Debugf("jwtCookie from querystring %s: %s", cfg.Cfg.Headers.SSO, jwt)
	}
	return jwt
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
		error401(w, r, AuthError{Error: "no jwt found"})
		return
	}

	claims, err := ClaimsFromJWT(jwt)
	if err != nil {
		// no email in jwt
		error401(w, r, AuthError{err.Error(), jwt})
		return
	}
	if claims.Email == "" {
		// no email in jwt
		error401(w, r, AuthError{"no email found in jwt", jwt})
		return
	}
	log.Infof("email from jwt cookie: %s", claims.Email)

	if !jwtmanager.SiteInClaims(r.Host, &claims) {
		error401(w, r, AuthError{"not authorized for " + r.Host, jwt})
		return
	}

	// renderIndex(w, "user found from email "+user.Email)
	renderIndex(w, "user found in jwt "+claims.Email)

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

	// set the state varialbe in the session
	var state = randString()
	session.Values["state"] = state
	log.Debugf("session state set to %s", session.Values["state"])

	// increment the failure counter for this domain

	// redirectURL comes from nginx in the query string
	var redirectURL = r.URL.Query().Get("url")
	if redirectURL != "" {
		// TODO store the originally requested URL so we can redirec on the roundtrip
		session.Values["requestedURL"] = redirectURL
		log.Debugf("session requestedURL set to %s", session.Values["requestedURL"])
	}

	// stop them after three failures for this URL
	var failcount = 0
	if session.Values[redirectURL] != nil {
		failcount = session.Values[redirectURL].(int)
		log.Debugf("failcount for %s is %d", redirectURL, failcount)
	}
	failcount++
	session.Values[redirectURL] = failcount

	log.Debug("saving session")
	session.Save(r, w)

	if failcount > 2 {
		var lassoError = r.URL.Query().Get("error")
		renderIndex(w, "too many redirects for "+redirectURL+" - "+lassoError)
	} else {
		// bounce to google for login
		var googleURL = loginURL(r, state)
		log.Debugf("redirecting to Google %s", googleURL)
		context.WithValue(r.Context(), lctx.StatusCode, 302)
		http.Redirect(w, r, googleURL, 302)
		// c.Writer.Write([]byte("<html><title>Golang Google</title> <body> <a href='" + url + "'><button>Login with Google!</button> </a> </body></html>"))
	}

}

func renderIndex(w http.ResponseWriter, msg string) {
	if err := indexTemplate.Execute(w, &Index{Msg: msg}); err != nil {
		log.Error(err)
	}
}

// VerifyUser validates that the domains match for the user
func VerifyUser(u structs.User) (ok bool, err error) {
	// (w http.ResponseWriter, req http.Request)
	// is Hd google specific? probably yes
	// TODO rewrite / abstract this validation
	ok = false
	if !domains.IsUnderManagement(u.Email) {
		err = fmt.Errorf("Email %s is not within a lasso managed domain", u.Email)
	} else if !domains.IsUnderManagement(u.HostDomain) {
		err = fmt.Errorf("HostDomain %s is not within a lasso managed domain", u.HostDomain)
	} else {
		ok = true
	}
	return ok, err
}

// GCallbackHandler /auth
// - validate info from Google
// - create user
// - issue jwt in the form of a cookie
func GCallbackHandler(w http.ResponseWriter, r *http.Request) {
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
		renderIndex(w, "Invalid session state.")
		return
	}

	gtoken, err := oauthclient.Exchange(oauth2.NoContext, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// make the "third leg" request back to google to exchange the token for the userinfo
	client := oauthclient.Client(oauth2.NoContext, gtoken)
	userinfo, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer userinfo.Body.Close()
	data, _ := ioutil.ReadAll(userinfo.Body)

	log.Println("userinfo body: ", string(data))
	user := structs.User{}
	if err = json.Unmarshal(data, &user); err != nil {
		log.Errorln(err)
		renderIndex(w, "Error marshalling response. Please try agian.")
		// c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": })
		return
	}

	if ok, err := VerifyUser(user); !ok {
		log.Error(err)
		renderIndex(w, fmt.Sprintf("User is not authorized. %s Please try agian.", err))
		return
	}

	// SUCCESS!! they are authorized

	// store the user in the database
	model.PutUser(user)

	// issue the jwt
	tokenstring := jwtmanager.CreateUserTokenString(user)
	cookie.SetCookie(w, r, tokenstring)

	// get the originally requested URL so we can send them on their way
	redirectURL := session.Values["requestedURL"].(string)
	if redirectURL != "" {
		// clear out the session value
		session.Values["requestedURL"] = ""
		session.Values[redirectURL] = 0
		session.Save(r, w)

		// and redirect
		context.WithValue(r.Context(), lctx.StatusCode, 302)
		http.Redirect(w, r, redirectURL, 302)
		return
	}
	// otherwise serve an html page
	renderIndex(w, tokenstring)
}
