package model

// modeled after
// https://www.opsdash.com/blog/persistent-key-value-store-golang.html

import (
	"errors"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/boltdb/bolt"
	"github.com/vouch/vouch-proxy/pkg/cfg"
)

var (
	// ErrNotFound is returned when the key supplied to a Get or Delete
	// method does not exist in the database.
	ErrNotFound = errors.New("key not found")

	// ErrBadValue is returned when the value supplied to the Put method
	// is nil.
	ErrBadValue = errors.New("bad value")

	//Db holds the db
	Db *bolt.DB

	dbpath string

	userBucket = []byte("users")
	teamBucket = []byte("teams")
	siteBucket = []byte("sites")
)

// may want to use encode/gob to store the user record
func init() {
	dbpath = os.Getenv("VOUCH_ROOT") + cfg.Cfg.DB.File
	Db, _ = OpenDB(dbpath)
}

// OpenDB the boltdb
func OpenDB(dbfile string) (*bolt.DB, error) {

	opts := &bolt.Options{
		Timeout: 50 * time.Millisecond,
	}

	db, err := bolt.Open(dbfile, 0644, opts)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return db, nil

}

func getBucket(tx *bolt.Tx, key []byte) *bolt.Bucket {
	b, err := tx.CreateBucketIfNotExists(key)
	if err != nil {
		log.Errorf("could not create bucket in db %s", err)
		log.Errorf("check the dbfile permissions at %s", dbpath)
		log.Errorf("if there's really something wrong with the data ./do.sh includes a utility to browse the dbfile")
		return nil
	}
	return b
}
