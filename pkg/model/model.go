package model

// modeled after
// https://www.opsdash.com/blog/persistent-key-value-store-golang.html

import (
	"bytes"
	"encoding/gob"
	"errors"
	"os"
	"time"

	"git.fs.bnf.net/bnfinet/lasso/pkg/cfg"
	"git.fs.bnf.net/bnfinet/lasso/pkg/structs"
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
)

// the result goes into this buffer
var buf bytes.Buffer

// make an encoder that will write into the buffer
var encoder *gob.Encoder

// may want to use encode/gob to store the user record
func init() {
	encoder = gob.NewEncoder(&buf)
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

// PutUser inna da db
func PutUser(u structs.User) {
	// store some data

	Db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(userBucket)
		if err != nil {
			return err
		}
		encoder.Encode(u) // stores u in buf
		out := buf.Bytes()
		log.Debugf("last bytes %s", out[len(out)-20:len(out)])

		err = bucket.Put([]byte(u.Email), out)
		if err != nil {
			return err
		}
		return nil
	})
}

// GetUser lookup user from key
func User(key string, v interface{}) error {
	return Db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket)
		val := b.Get([]byte(key))
		gob.NewDecoder(bytes.NewReader(val)).Decode(v)
		log.Debugf("retrieved %s from db", v.(*structs.User).Email)
		return nil
	})
}
