package model

// modeled after
// https://www.opsdash.com/blog/persistent-key-value-store-golang.html

import (
	"errors"
	"flag"
	"path/filepath"
	"time"

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

	// dbpath string

	userBucket = []byte("users")
	teamBucket = []byte("teams")
	siteBucket = []byte("sites")
	dbpath     = filepath.Join(cfg.RootDir, cfg.Cfg.DB.File)

	log = cfg.Cfg.Logger
)

// may want to use encode/gob to store the user record
func init() {
	// in testing we open the dbfile from _test.go explicitly
	if flag.Lookup("test.v") != nil {
		return
	}
	Db, _ = OpenDB(dbpath)
}

// OpenDB the boltdb
func OpenDB(dbfile string) (*bolt.DB, error) {

	log.Debugf("opening dbfile %s", dbfile)

	opts := &bolt.Options{
		Timeout: 50 * time.Millisecond,
	}

	db, err := bolt.Open(dbfile, 0644, opts)
	if err != nil {
		log.Panicf("unable to open dbfile %s: %s", dbfile, err.Error())
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
