package model

// modeled after
// https://www.opsdash.com/blog/persistent-key-value-store-golang.html

import (
	"errors"
	"os"
	"time"

	"github.com/bnfinet/lasso/pkg/cfg"
	log "github.com/Sirupsen/logrus"
	"github.com/boltdb/bolt"
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

	userBucket = []byte("users")
	teamBucket = []byte("teams")
	siteBucket = []byte("sites")
)

// may want to use encode/gob to store the user record
func init() {
	Db, _ = Open(os.Getenv("LASSO_ROOT") + cfg.Cfg.DB.File)
}

// Open the boltdb
func Open(dbfile string) (*bolt.DB, error) {

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
		log.Errorf("could not create bucket %s", err)
		return nil
	}
	return b
}
