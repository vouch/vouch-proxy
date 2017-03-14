package storage

// modeled after
// https://www.opsdash.com/blog/persistent-key-value-store-golang.html

import (
	"os"
	"testing"

	// log "github.com/Sirupsen/logrus"

	"github.com/stretchr/testify/assert"

	"git.fs.bnf.net/bnfinet/lasso/lib/structs"
)

var testdb = "storage-test.db"

func init() {
	// log.SetLevel(log.DebugLevel)
}

func TestPutUserGetUser(t *testing.T) {
	os.Remove(testdb)
	Open(testdb)

	u1 := structs.User{
		Email:         "test@testing.com",
		EmailVerified: true,
		Name:          "Test Name",
	}

	PutUser(u1)
	u2 := structs.User{}
	GetUser(u1.Email, &u2)
	assert.Equal(t, u1.Email, u2.Email)
}
