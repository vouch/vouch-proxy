package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	log "github.com/Sirupsen/logrus"

	"git.fs.bnf.net/bnfinet/lasso/lib/cfg"
	"git.fs.bnf.net/bnfinet/lasso/lib/cookie"
	"git.fs.bnf.net/bnfinet/lasso/lib/domains"
	"git.fs.bnf.net/bnfinet/lasso/lib/jwtmanager"
	"git.fs.bnf.net/bnfinet/lasso/lib/storage"
	"git.fs.bnf.net/bnfinet/lasso/lib/structs"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	gcred       structs.GCredentials
	oauthclient *oauth2.Config

	sessstore = sessions.NewCookieStore([]byte(cfg.Cfg.Session.Name))
)

func init() {
	cfg.UnmarshalKey("google", &gcred)

	oauthclient = &oauth2.Config{
		ClientID:     gcred.ClientID,
		ClientSecret: gcred.ClientSecret,
		RedirectURL:  gcred.RedirectURL,
		Scopes: []string{
			// You have to select a scope from
			// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

func randString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func loginURL(state string) string {
	// State can be some kind of random generated hash string.
	// See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12
	var url = oauthclient.AuthCodeURL(state)
	// log.Debugf("loginUrl %s", url)
	return url
}

// IndexHandler /
func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.tmpl", gin.H{})
}

func emailFromCookieJWT(c *gin.Context) (string, error) {
	// get jwt from cookie.name
	// parse the jwt
	jwtCookie, err := cookie.Cookie(c)
	if err != nil {
		return "", err
	}
	log.Debugf("jwtCookie from cookie: %s", jwtCookie)
	if jwtCookie == "" {
		jwtCookie = c.Request.Header.Get(cfg.Cfg.Headers.SSO)
		log.Debugf("jwtCookie from header %s: %s", cfg.Cfg.Headers.SSO, jwtCookie)
	}
	jwtParsed, err := jwtmanager.ParseTokenString(jwtCookie)
	if err != nil {
		// it didn't parse, which means its bad, start over
		log.Error("jwtParsed returned error, clearing cookie")
		cookie.ClearCookie(c)
		return "", err
	}

	email, err := jwtmanager.PTokenToEmail(jwtParsed)
	if err != nil {
		return "", err
	}
	return email, nil
}

// the standard error
// this is captured by nginx and results in a 302 to the login page
func error401(c *gin.Context, errStr string) {
	// cookie.ClearCookie(c)
	http.Error(c.Writer, errStr, http.StatusUnauthorized)
	// TODO put this back in place if multiple auth mechanism are available
	// c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": errStr})
}

func error401na(c *gin.Context) {
	error401(c, "not authorized")
}

// AuthRequestHandler /authrequest
func AuthRequestHandler(c *gin.Context) {
	log.Debug("/authrequest")
	email, err := emailFromCookieJWT(c)
	if err != nil {
		// no email in jwt
		error401(c, err.Error())
		return
	}
	log.Infof("email from jwt cookie: %s", email)

	user := structs.User{}
	err = storage.GetUser(email, &user)
	if err != nil {
		// no email in jwt
		error401(c, err.Error())
		return
	}

	c.HTML(http.StatusOK, "index.tmpl", gin.H{"extra": "user found from email " + user.Email})
}

// LoginHandler /login
// currently performs a 302 redirect to Google
func LoginHandler(c *gin.Context) {
	log.Debug("/login")
	// no matter how you ended up here, make sure the cookie gets cleared out
	cookie.ClearCookie(c)

	session, err := sessstore.Get(c.Request, cfg.Cfg.Session.Name)
	if err != nil {
		log.Error(err)
	}

	// set the state varialbe in the session
	var state = randString()
	session.Values["state"] = state
	log.Debugf("session state set to %s", session.Values["state"])

	// redirectURL comes from nginx in the query string
	var redirectURL = c.Query("url")
	if redirectURL != "" {
		// TODO store the originally requested URL so we can redirec on the roundtrip
		session.Values["requestedURL"] = redirectURL
		log.Debugf("session requestedURL set to %s", session.Values["requestedURL"])
	}

	log.Debug("saving session")
	session.Save(c.Request, c.Writer)

	// bounce to google for login
	var googleURL = loginURL(state)
	log.Debugf("redirecting to Google %s", googleURL)
	c.Redirect(302, googleURL)
	// c.Writer.Write([]byte("<html><title>Golang Google</title> <body> <a href='" + url + "'><button>Login with Google!</button> </a> </body></html>"))
}

// VerifyUser validates that the domains match for the user
func VerifyUser(u structs.User) (ok bool, err error) {
	// is Hd google specific? probably yes
	// TODO rewrite / abstract this validation
	ok = false
	if !domains.DomainUnderManagement(u.Email) {
		err = fmt.Errorf("Email %s is not within a lasso managed domain", u.Email)
	} else if !domains.DomainUnderManagement(u.HostDomain) {
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
func GCallbackHandler(c *gin.Context) {
	log.Debug("/auth")
	// Handle the exchange code to initiate a transport.

	session, err := sessstore.Get(c.Request, cfg.Cfg.Session.Name)
	if err != nil {
		log.Errorf("could not find session store %s", cfg.Cfg.Session.Name)
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}

	// is the nonce "state" valid?
	queryState := c.Query("state")
	if session.Values["state"] != queryState {
		log.Errorf("Invalid session state: stored %s, returned %s", session.Values["state"], queryState)
		c.HTML(http.StatusUnauthorized, "error.tmpl", gin.H{"message": "Invalid session state."})
		return
	}

	gtoken, err := oauthclient.Exchange(oauth2.NoContext, c.Query("code"))
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	// make the "third leg" request back to google to exchange the tokent get the userinfo
	client := oauthclient.Client(oauth2.NoContext, gtoken)
	userinfo, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	defer userinfo.Body.Close()
	data, _ := ioutil.ReadAll(userinfo.Body)

	log.Println("userinfo body: ", string(data))
	user := structs.User{}
	if err = json.Unmarshal(data, &user); err != nil {
		log.Errorln(err)
		c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": "Error marshalling response. Please try agian."})
		return
	}

	if ok, err := VerifyUser(user); !ok {
		log.Error(err)
		c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": fmt.Sprintf("User is not authorized. %s Please try agian.", err)})
		return
	}

	// SUCCESS!! they are authorized

	// store the user
	storage.PutUser(user)

	// issue the jwt
	tokenstring := jwtmanager.CreateUserTokenString(user)
	cookie.SetCookie(c, tokenstring)

	// TODO store the originally requested URL so we can redirect on the roundtrip
	redirectURL := session.Values["requestedURL"].(string)
	if redirectURL != "" {
		// clear out the session value
		session.Values["requestedURL"] = ""
		session.Save(c.Request, c.Writer)

		// and redirect
		c.Redirect(302, redirectURL)
		return
	}

	c.HTML(http.StatusOK, "index.tmpl", gin.H{"extra": tokenstring})
}

// FieldHandler is a rudementary handler for logged in users.
func FieldHandler(c *gin.Context) {
	// session := sessions.Default(c)
	// userID := session.Get("user-id")
	c.HTML(http.StatusOK, "field.tmpl", gin.H{"user": "userID"})
}
