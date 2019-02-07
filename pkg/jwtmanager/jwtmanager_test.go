package jwtmanager

import (
	"testing"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"

	// log "github.com/Sirupsen/logrus"
	log "github.com/Sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	u1 = structs.User{
		Username: "test@testing.com",
		Name:     "Test Name",
	}

	lc VouchClaims
)

func init() {
	// log.SetLevel(log.DebugLevel)

	lc = VouchClaims{
		u1.Username,
		Sites,
		u1.IDToken,
		u1.AccessToken,
		StandardClaims,
	}
}

func TestCreateUserTokenStringAndParseToUsername(t *testing.T) {

	uts := CreateUserTokenString(u1)
	assert.NotEmpty(t, uts)

	utsParsed, err := ParseTokenString(uts)
	if utsParsed == nil || err != nil {
		t.Error(err)
	} else {
		log.Debugf("test parsed token string %v", utsParsed)
		ptUsername, _ := PTokenToUsername(utsParsed)
		assert.Equal(t, u1.Username, ptUsername)
	}

}

func TestClaims(t *testing.T) {
	cfg.ParseConfig()

	log.Debugf("jwt config %s %d", string(cfg.Cfg.JWT.Secret), cfg.Cfg.JWT.MaxAge)
	assert.NotEmpty(t, cfg.Cfg.JWT.Secret)
	assert.NotEmpty(t, cfg.Cfg.JWT.MaxAge)

	// now := time.Now()
	// d := time.Duration(ExpiresAtMinutes) * time.Minute
	// log.Infof("lc d %s", d.String())
	// lc.StandardClaims.ExpiresAt = now.Add(time.Duration(ExpiresAtMinutes) * time.Minute).Unix()
	// log.Infof("lc expiresAt %d", now.Unix()-lc.StandardClaims.ExpiresAt)
	uts := CreateUserTokenString(u1)
	utsParsed, _ := ParseTokenString(uts)
	assert.True(t, SiteInToken("naga.bnf.net", utsParsed))

}
