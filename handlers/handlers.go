package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	log "github.com/Sirupsen/logrus"

	// "os"

	"github.com/gorilla/sessions"

	"git.fs.bnf.net/bnfinet/lasso/lib/cfg"
	"git.fs.bnf.net/bnfinet/lasso/lib/cookie"
	"git.fs.bnf.net/bnfinet/lasso/lib/jwtmanager"
	"git.fs.bnf.net/bnfinet/lasso/lib/storage"
	"git.fs.bnf.net/bnfinet/lasso/lib/structs"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	gcred          structs.GCredentials
	oauthclient    *oauth2.Config
	sessCookieName string
	ssoHeaderName  string

	sessstore = sessions.NewCookieStore([]byte(cfg.Get("session.cookiename")))

	// this is to fake state management until we get something better in place
	// retrievedState string
	// userID         string
)

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func loginURL(state string) string {
	// State can be some kind of random generated hash string.
	// See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12
	var url = oauthclient.AuthCodeURL(state)
	log.Infof("url %s", url)
	return url
}

func init() {
	cfg.UnmarshalKey("google", &gcred)
	sessCookieName = cfg.Get("session.fieldname")
	ssoHeaderName = cfg.Get("header")

	oauthclient = &oauth2.Config{
		ClientID:     gcred.ClientID,
		ClientSecret: gcred.ClientSecret,
		RedirectURL:  gcred.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email", // You have to select your own scope from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		},
		Endpoint: google.Endpoint,
	}
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
	log.Infof("jwtCookie from cookie: %s", jwtCookie)
	if jwtCookie == "" {
		jwtCookie = c.Request.Header.Get(ssoHeaderName)
		log.Infof("jwtCookie from header %s: %s", ssoHeaderName, jwtCookie)
	}
	jwtParsed, err := jwtmanager.ParseTokenString(jwtCookie)
	if err != nil {
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
	// TODO put this back i place
	http.Error(c.Writer, errStr, http.StatusUnauthorized)
	// c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": errStr})
}

func error401na(c *gin.Context) {
	error401(c, "not authorized")
}

// AuthRequestHandler /authrequest
func AuthRequestHandler(c *gin.Context) {
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

// GCallbackHandler /auth
// - validate info from Google
// - create user
// - issue jwt in the form of a cookie
func GCallbackHandler(c *gin.Context) {
	// Handle the exchange code to initiate a transport.

	session, err := sessstore.Get(c.Request, sessCookieName)
	if err != nil {
		http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
		return
	}

	queryState := c.Query("state")

	if session.Values["state"] != queryState {
		log.Errorf("Invalid session state: stored %s, returned %s", session.Values["state"], queryState)
		c.HTML(http.StatusUnauthorized, "error.tmpl", gin.H{"message": "Invalid session state."})
		return
	}

	tok, err := oauthclient.Exchange(oauth2.NoContext, c.Query("code"))
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	// get the userinfo
	client := oauthclient.Client(oauth2.NoContext, tok)
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
		log.Println(err)
		c.HTML(http.StatusBadRequest, "error.tmpl", gin.H{"message": "Error marshalling response. Please try agian."})
	}

	// store the user
	storage.PutUser(user)

	// issue the jwt
	tokenstring := jwtmanager.CreateUserTokenString(user)
	cookie.SetCookie(c, tokenstring, c.Request.URL.Host)

	// TODO store the originally requested URL so we can redirec on the roundtrip
	redirectURL := session.Values["requestedURL"].(string)
	if redirectURL != "" {
		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
		// = "http://bnf.net/?requested=" + state
	}

	c.HTML(http.StatusOK, "index.tmpl", gin.H{"extra": tokenstring})
}

func LoginHandler(c *gin.Context) {

	state := randToken()
	// set the state varialbe in the session

	session, err := sessstore.Get(c.Request, sessCookieName)
	if err != nil {
		log.Error(err)
	}
	session.Values["state"] = state
	// TODO store the originally requested URL so we can redirec on the roundtrip
	session.Values["requestedURL"] = "http://bnf.net/?requested=" + state
	session.Save(c.Request, c.Writer)

	var url = loginURL(state)
	log.Debugf("url %s", url)
	c.Writer.Write([]byte("<html><title>Golang Google</title> <body> <a href='" + url + "'><button>Login with Google!</button> </a> </body></html>"))
}

// FieldHandler is a rudementary handler for logged in users.
func FieldHandler(c *gin.Context) {
	// session := sessions.Default(c)
	// userID := session.Get("user-id")
	c.HTML(http.StatusOK, "field.tmpl", gin.H{"user": "userID"})
}
