package cookie

import (
	"errors"

	// "git.fs.bnf.net/bnfinet/lasso/lib/structs"
	"git.fs.bnf.net/bnfinet/lasso/lib/cfg"
	"git.fs.bnf.net/bnfinet/lasso/lib/domains"
	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

// SetCookie set the lasso jwt cookie
func SetCookie(c *gin.Context, val string) {
	// foreach domain
	domain := domains.Matches(c.Request.Host)
	var expires = cfg.Cfg.JWT.MaxAge * 60
	log.Debugf("cookie %s expires %d", cfg.Cfg.Cookie.Name, expires)
	c.SetCookie(cfg.Cfg.Cookie.Name,
		val,
		expires,
		"/",
		domain,
		cfg.Cfg.Cookie.Secure,
		cfg.Cfg.Cookie.HTTPOnly)
}

// Cookie get the lasso jwt cookie
func Cookie(c *gin.Context) (string, error) {
	cookie, err := c.Cookie(cfg.Cfg.Cookie.Name)
	if err != nil {
		return "", err
	}
	if cookie == "" {
		return "", errors.New("Cookie token empty")
	}
	log.Debugf("cookie %s: %s", cfg.Cfg.Cookie.Name, cookie)
	return cookie, err
}

// ClearCookie get rid of the existing cookie
func ClearCookie(c *gin.Context) {
	domain := domains.Matches(c.Request.Host)
	log.Debugf("clearing cookie %s in %s", cfg.Cfg.Cookie.Name, domain)
	c.SetCookie(cfg.Cfg.Cookie.Name,
		"delete",
		-1,
		"/",
		domain,
		cfg.Cfg.Cookie.Secure,
		cfg.Cfg.Cookie.HTTPOnly)
}
