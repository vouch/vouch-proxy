/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vouch/vouch-proxy/pkg/cookie"

	"github.com/stretchr/testify/assert"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
)

var (
	token = &oauth2.Token{AccessToken: "123"}
)

func setUp(configFile string) {
	os.Setenv("VOUCH_CONFIG", filepath.Join(os.Getenv("VOUCH_ROOT"), configFile))
	cfg.InitForTestPurposes()

	// cfg.Cfg.AllowAllUsers = false
	// cfg.Cfg.WhiteList = make([]string, 0)
	// cfg.Cfg.TeamWhiteList = make([]string, 0)
	// cfg.Cfg.Domains = []string{"domain1"}

	Configure()

	domains.Configure()
	jwtmanager.Configure()
	cookie.Configure()

}

func TestVerifyUserPositiveUserInWhiteList(t *testing.T) {
	setUp("/config/testing/handler_whitelist.yml")
	user := &structs.User{Username: "test@example.com", Email: "test@example.com", Name: "Test Name"}
	ok, err := verifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveAllowAllUsers(t *testing.T) {
	setUp("/config/testing/handler_allowallusers.yml")

	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}

	ok, err := verifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByEmail(t *testing.T) {
	setUp("/config/testing/handler_email.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	ok, err := verifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByTeam(t *testing.T) {
	setUp("/config/testing/handler_teams.yml")

	// cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team2", "org1/team1")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	user.TeamMemberships = append(user.TeamMemberships, "org1/team3")
	user.TeamMemberships = append(user.TeamMemberships, "org1/team1")
	ok, err := verifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegativeByTeam(t *testing.T) {
	setUp("/config/testing/handler_teams.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	// cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team1")

	ok, err := verifyUser(*user)
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestVerifyUserPositiveNoDomainsConfigured(t *testing.T) {
	setUp("/config/testing/handler_nodomains.yml")

	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	cfg.Cfg.Domains = make([]string, 0)
	ok, err := verifyUser(*user)

	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegative(t *testing.T) {
	setUp("/config/testing/test_config.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	ok, err := verifyUser(*user)

	assert.False(t, ok)
	assert.NotNil(t, err)
}
