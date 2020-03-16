package handlers

import (
	"github.com/stretchr/testify/assert"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
	"testing"
)

var (
	user  *structs.User
	token = &oauth2.Token{AccessToken: "123"}
)

func init() {
	setUp()
}

func setUp() {
	cfg.InitForTestPurposes()

	cfg.Cfg.AllowAllUsers = false
	cfg.Cfg.WhiteList = make([]string, 0)
	cfg.Cfg.TeamWhiteList = make([]string, 0)
	cfg.Cfg.Domains = []string{"domain1"}

	domains.Refresh()

	user = &structs.User{Username: "testuser", Email: "test@example.com"}
}

func TestVerifyUserPositiveUserInWhiteList(t *testing.T) {
	setUp()
	cfg.Cfg.WhiteList = append(cfg.Cfg.WhiteList, user.Username)

	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveAllowAllUsers(t *testing.T) {
	setUp()
	cfg.Cfg.AllowAllUsers = true

	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByEmail(t *testing.T) {
	setUp()
	cfg.Cfg.Domains = append(cfg.Cfg.Domains, "example.com")
	domains.Refresh()

	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByTeam(t *testing.T) {
	setUp()
	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team2", "org1/team1")

	user.TeamMemberships = append(user.TeamMemberships, "org1/team3")
	user.TeamMemberships = append(user.TeamMemberships, "org1/team1")
	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegativeByTeam(t *testing.T) {
	setUp()
	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team1")

	ok, err := VerifyUser(*user)
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestVerifyUserPositiveNoDomainsConfigured(t *testing.T) {
	setUp()
	cfg.Cfg.Domains = make([]string, 0)

	ok, err := VerifyUser(*user)

	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegative(t *testing.T) {
	setUp()

	ok, err := VerifyUser(*user)

	assert.False(t, ok)
	assert.NotNil(t, err)
}
