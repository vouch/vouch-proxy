package cookie

import (
	"errors"

	"git.fs.bnf.net/bnfinet/lasso/lib/cfg"
	// "git.fs.bnf.net/bnfinet/lasso/lib/structs"
	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

// Cfg lasso jwt cookie configuration
type Cfg struct {
	Name     string `mapstructure:"name"`
	MaxAge   int    `mapstructure:"maxAge"`
	Secure   bool   `mapstructure:"secure"`
	HTTPOnly bool   `mapstructure:"httpOnly"`
}

var cCfg Cfg

func init() {
	cfg.UnmarshalKey("cookie", &cCfg)
}

// SetCookie set the lasso jwt cookie
func SetCookie(c *gin.Context, val string, domain string) {
	// foreach domain
	c.SetCookie(cCfg.Name, val, cCfg.MaxAge, "/", domain, cCfg.Secure, cCfg.HTTPOnly)
}

// Cookie get the lasso jwt cookie
func Cookie(c *gin.Context) (string, error) {
	cookie, err := c.Cookie(cCfg.Name)
	if err != nil {
		return "", err
	}
	if cookie == "" {
		return "", errors.New("Cookie token empty")
	}
	log.Infof("cookie %s: %s", cCfg.Name, cookie)
	return cookie, err
}
