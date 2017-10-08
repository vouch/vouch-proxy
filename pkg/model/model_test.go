package model

// modeled after
// https://www.opsdash.com/blog/persistent-key-value-store-golang.html

import (
	"os"
	"testing"

	log "github.com/Sirupsen/logrus"

	"github.com/stretchr/testify/assert"

	"github.com/bnfinet/lasso/pkg/structs"
)

var testdb = "/tmp/storage-test.db"

func init() {
	Db, _ = Open(testdb)

	log.SetLevel(log.DebugLevel)
}

func TestPutUserGetUser(t *testing.T) {
	os.Remove(testdb)
	Open(testdb)

	u1 := structs.User{
		Email: "test@testing.com",
		Name:  "Test Name",
	}
	u2 := &structs.User{}
	u3 := structs.User{
		Email: "testagain@testing.com",
		Name:  "Test Again",
	}

	if err := PutUser(u1); err != nil {
		log.Error(err)
	}
	User([]byte(u1.Email), u2)
	if err := PutUser(u3); err != nil {
		log.Error(err)
	}
	log.Debugf("user retrieved: %v", *u2)
	assert.Equal(t, u1.Email, u2.Email)

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
	Open(testdb)

	s1 := structs.Site{Domain: "test.bnf.net"}
	s2 := &structs.Site{}

	if err := PutSite(s1); err != nil {
		log.Error(err)
	}
	Site([]byte(s1.Domain), s2)
	log.Debugf("site retrieved: %v", *s2)
	assert.Equal(t, s1.Domain, s2.Domain)
}

func TestPutTeamGetTeam(t *testing.T) {
	os.Remove(testdb)
	Open(testdb)

	t1 := structs.Team{Name: "testname"}
	t2 := &structs.Team{}

	if err := PutTeam(t1); err != nil {
		log.Error(err)
	}
	Team([]byte(t1.Name), t2)
	log.Debugf("team retrieved: %v", *t2)
	assert.Equal(t, t1.Name, t2.Name)
}
