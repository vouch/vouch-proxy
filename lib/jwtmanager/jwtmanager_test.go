package jwtmanager

import (
	"testing"

	"git.fs.bnf.net/bnfinet/lasso/lib/structs"
	// log "github.com/Sirupsen/logrus"

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
	// log.SetLevel(log.DebugLevel)
}

func TestCreateUserTokenStringAndParseToEmail(t *testing.T) {

	uts := CreateUserTokenString(u1)

	utsParsed, err := ParseTokenString(uts)
	if err != nil {
		t.Error(err)
	}

	ptemail, err := PTokenToEmail(utsParsed)
	assert.Equal(t, u1.Email, ptemail)

}
