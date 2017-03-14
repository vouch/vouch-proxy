package jwtmanager

import (
	"testing"

	"git.fs.bnf.net/bnfinet/lasso/lib/cfg"
	"git.fs.bnf.net/bnfinet/lasso/lib/structs"
	// log "github.com/Sirupsen/logrus"
	log "github.com/Sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	u1 = structs.User{
		Email:         "test@testing.com",
		EmailVerified: true,
		Name:          "Test Name",
	}

	lc = LassoClaims{
		u1.Email,
		StandardClaims,
	}
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestCreateUserTokenStringAndParseToEmail(t *testing.T) {

	uts := CreateUserTokenString(u1)
	assert.NotEmpty(t, uts)

	utsParsed, err := ParseTokenString(uts)
	if utsParsed == nil || err != nil {
		t.Error(err)
	} else {
		ptemail, _ := PTokenToEmail(utsParsed)
		assert.Equal(t, u1.Email, ptemail)
	}

}

func TestClaims(t *testing.T) {

	log.Debugf("jwt config %s %d", string(cfg.Cfg.JWT.Secret), cfg.Cfg.JWT.MaxAge)
	assert.NotEmpty(t, cfg.Cfg.JWT.Secret)
	assert.NotEmpty(t, cfg.Cfg.JWT.MaxAge)

	// now := time.Now()
	// d := time.Duration(ExpiresAtMinutes) * time.Minute
	// log.Infof("lc d %s", d.String())
	// lc.StandardClaims.ExpiresAt = now.Add(time.Duration(ExpiresAtMinutes) * time.Minute).Unix()
	// log.Infof("lc expiresAt %d", now.Unix()-lc.StandardClaims.ExpiresAt)

}
