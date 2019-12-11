package model

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

// PutUser inna da db
func PutUser(u structs.User) error {
	userexists := false
	curu := &structs.User{}
	if u.Username != "" {
		err := User([]byte(u.Username), curu)
		if err == nil {
			userexists = true
		} else {
			log.Errorw("PutUser userexists lookup error",
				"error", err.Error(),
				"userexists", userexists,
				"u", u,
				"curu", curu,
			)
		}
	}

	return Db.Update(func(tx *bolt.Tx) error {
		b := getBucket(tx, userBucket)

		u.LastUpdate = time.Now().Unix()
		if userexists {
			log.Debugf("userexists.. keeping time at %v", curu.CreatedOn)
			u.CreatedOn = curu.CreatedOn
		} else {
			u.CreatedOn = u.LastUpdate
			id, _ := b.NextSequence()
			u.ID = strconv.Itoa(int(id))
			log.Debugf("new user.. setting created on to %v", u.CreatedOn)
		}

		eU, err := gobEncodeUser(&u)
		if err != nil {
			log.Error(err)
			return err
		}

		err = b.Put([]byte(u.Username), eU)
		if err != nil {
			log.Error(err)
			return err
		}
		log.Debugf("user created %v", u)
		return nil
	})
}

// User lookup user from key
func User(key []byte, u *structs.User) error {
	log.Debugf("looking up User %s", key)
	return Db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(userBucket); b != nil {
			log.Debugf("key is %s", key)
			val := b.Get([]byte(key))
			user, err := gobDecodeUser(val)
			if err != nil {
				return err
			}
			*u = *user
			log.Debugf("retrieved %s from db", u.Username)
			return nil
		}
		return fmt.Errorf("no bucket for %s", userBucket)
	})
}

// AllUsers collect all items
func AllUsers(users *[]structs.User) error {
	return Db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(userBucket); b != nil {
			if err := b.ForEach(func(k, v []byte) error {
				log.Debugf("key=%s, value=%s\n", k, v)
				u := structs.User{}
				if err := User(k, &u); err != nil {
					log.Error(err)
				}
				*users = append(*users, u)
				return nil
			}); err != nil {
				log.Error(err)
			}
			log.Debugf("users %v", users)
			return nil
		}
		return fmt.Errorf("no bucket for %s", userBucket)
	})
}

func gobEncodeUser(u *structs.User) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(u)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gobDecodeUser(data []byte) (*structs.User, error) {
	u := &structs.User{}
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(u)
	if err != nil {
		return nil, err
	}
	return u, nil
}
