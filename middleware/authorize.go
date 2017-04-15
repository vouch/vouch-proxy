package middleware

// TODO use this middleware and the main.go call to build out the management interface

import (
	// "net/http"

	// "git.fs.bnf.net/bnfinet/lasso/pkg/cfg"
	"git.fs.bnf.net/bnfinet/lasso/pkg/cookie"
	jwtmanager "git.fs.bnf.net/bnfinet/lasso/pkg/jwtmanager"
	log "github.com/Sirupsen/logrus"
	jwt "github.com/dgrijalva/jwt-go"

	"github.com/gin-gonic/gin"
)

// AuthorizeRequest is used to authorize a request for a certain end-point group.
func AuthorizeRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := jwtFromCookie(c)
		if err != nil {
			c.Redirect(302, "/login")
			// c.HTML(http.StatusUnauthorized, "error.tmpl", gin.H{"message": "Please login."})
			c.Abort()
		}
		if !jwtmanager.TokenIsValid(token, err) {
			c.Redirect(302, "/login")
			c.Abort()
		}
		if !jwtmanager.TokenClaimsIncludeSite(token, c.Request.Host) {
			c.Redirect(302, "/login")
			c.Abort()
		}

		log.Debugf("token %s", token)
		c.Next()
	}
}

func jwtFromCookie(c *gin.Context) (*jwt.Token, error) {
	cookie, err := cookie.Cookie(c)
	if err != nil {
		log.Errorf("bad cookie %s", err)
		c.Abort()
	}
	token, err := jwtmanager.ParseTokenString(cookie)
	if err != nil {
		log.Errorf("bad jwt %s", err)
		c.Abort()
		return nil, err
	}

	return token, nil
}
