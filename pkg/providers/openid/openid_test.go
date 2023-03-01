package openid

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

func TestGetUserInfo(t *testing.T) {
	setUp()

	user := structs.User{
		Username:        "test",
		CreatedOn:       123,
		Email:           "email@example.com",
		ID:              1,
		LastUpdate:      123,
		Name:            "name",
		TeamMemberships: []string{"team1"},
	}

	// test1
	userinfobody := "{\"sub\":\"xx\",\"email\":\"email@example.com\",\"email_address\":\"email@example.com\",\"full_name\":\"ABC DEF\",\"last_name\":\"ABC\",\"CustomClaim1\":\"team2\"}"
	data := []byte(userinfobody)
	err := appendTeamMembershipsFromCustomClaim(data, &user)
	assert.ElementsMatchf(t, err, nil, "Expected error to be nil")
	assert.ElementsMatchf(t, user.TeamMemberships, []string{"team1", "team2"}, "Expected team memberships to be appended")

	//test2
	user.TeamMemberships = nil
	userinfobody = "{\"sub\":\"xx\",\"email\":\"email@example.com\",\"email_address\":\"email@example.com\",\"full_name\":\"ABC DEF\",\"last_name\":\"ABC\",\"CustomClaim1\":\"team2\"}"
	data = []byte(userinfobody)
	err = appendTeamMembershipsFromCustomClaim(data, &user)
	assert.ElementsMatchf(t, err, nil, "Expected error to be nil")
	assert.ElementsMatchf(t, user.TeamMemberships, []string{"team2"}, "Expected team memberships to be appended")

	//test3
	user.TeamMemberships = nil
	userinfobody = "{\"sub\":\"xx\",\"email\":\"email@example.com\",\"email_address\":\"email@example.com\",\"full_name\":\"ABC DEF\",\"last_name\":\"ABC\",\"CustomClaim1\":[\"team2\",\"team3\"]}"
	data = []byte(userinfobody)
	err = appendTeamMembershipsFromCustomClaim(data, &user)
	assert.ElementsMatchf(t, err, nil, "Expected error to be nil")
	assert.ElementsMatchf(t, user.TeamMemberships, nil, "Expected team memberships to be empty due to casting error")

}

func setUp() {
	log = cfg.Logging.Logger
	cfg.Cfg.TeamWhiteListClaim = "CustomClaim1"
}
