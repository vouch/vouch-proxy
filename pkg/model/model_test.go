package model

// modeled after
// https://www.opsdash.com/blog/persistent-key-value-store-golang.html

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

var testdb = "/tmp/storage-test.db"

func init() {
	cfg.InitForTestPurposes()

	Db, _ = OpenDB(testdb)
}

func TestPutUserGetUser(t *testing.T) {
	os.Remove(testdb)
	Db, _ = OpenDB(testdb)

	u1 := structs.User{
		Username: "test@testing.com",
		Name:     "Test Name",
	}
	u2 := &structs.User{}
	u3 := structs.User{
		Username: "testagain@testing.com",
		Name:     "Test Again",
	}

	if err := PutUser(u1); err != nil {
		log.Error("PutUser u1: " + err.Error())
	}
	User([]byte(u1.Username), u2)
	if err := PutUser(u3); err != nil {
		log.Error("PutUser u3: " + err.Error())
	}
	log.Debugf("user retrieved: %v", *u2)
	assert.Equal(t, u1.Username, u2.Username)

	if err := PutUser(u3); err != nil {
		log.Error(err)
	}
	var users []structs.User
	if err := AllUsers(&users); err != nil {
		log.Error(err)
	}
	assert.Len(t, users, 2)
}

func TestPutSiteGetSite(t *testing.T) {
	os.Remove(testdb)
	Db, _ = OpenDB(testdb)

	s1 := structs.Site{Domain: "test.bnf.net"}
	s2 := &structs.Site{}

	if err := PutSite(s1); err != nil {
		log.Error(err)
	}
	Site([]byte(s1.Domain), s2)
	log.Debugf("site retrieved: %v", *s2)
	assert.Equal(t, s1.Domain, s2.Domain)
}

func TestPutTeamGetTeamDeleteTeam(t *testing.T) {
	os.Remove(testdb)
	Db, _ = OpenDB(testdb)

	t1 := structs.Team{Name: "testteam1"}
	t2 := &structs.Team{}
	t3 := &structs.Team{}
	t4 := structs.Team{Name: "testteam4"}
	t5 := structs.Team{Name: "testteam5"}

	var err error
	if err = PutTeam(t1); err != nil {
		log.Error(err)
	}
	Team([]byte(t1.Name), t2)
	log.Debugf("team retrieved: %v", *t2)
	assert.Equal(t, t1.Name, t2.Name)

	if err = DeleteTeam(t1); err != nil {
		log.Error(err)
	}
	// should fail
	err = Team([]byte(t1.Name), t3)
	assert.Error(t, err)

	err = PutTeam(t1)
	assert.NoError(t, err)
	err = PutTeam(t4)
	assert.NoError(t, err)
	err = PutTeam(t5)
	assert.NoError(t, err)

	var teams []structs.Team
	err = AllTeams(&teams)
	log.Debugf("TestPutTeamGetTeamDeleteTeam:\nteam: %+v\nteams: %+v", t1, teams)
	// assert.NotContains(t, teams, t1)

	teamNames := make([]string, len(teams))
	for _, teamV := range teams {
		teamNames = append(teamNames, teamV.Name)
	}

	Team([]byte(t1.Name), &t1)
	assert.Contains(t, teamNames, t1.Name)

	// assert.Contains(t, teams, t4)
	// assert.Contains(t, teams, t5)

	assert.NoError(t, err)

}
