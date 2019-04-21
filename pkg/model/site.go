package model

import (
	"bytes"
	"encoding/gob"
	"time"

	"github.com/boltdb/bolt"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

// PutSite inna da db
func PutSite(s structs.Site) error {
	siteexists := false
	curs := &structs.Site{}
	err := Site([]byte(s.Domain), curs)
	if err != nil {
		log.Error(err)
	} else {
		siteexists = true
	}

	return Db.Update(func(tx *bolt.Tx) error {
		b := getBucket(tx, siteBucket)

		s.LastUpdate = time.Now().Unix()
		if siteexists {
			log.Debugf("siteexists.. keeping time at %v", curs.CreatedOn)
			s.CreatedOn = curs.CreatedOn
		} else {
			id, _ := b.NextSequence()
			s.ID = int(id)
			s.CreatedOn = s.LastUpdate
		}

		eS, err := gobEncodeSite(&s)
		if err != nil {
			log.Error(err)
			return err
		}

		err = b.Put([]byte(s.Domain), eS)
		if err != nil {
			return err
		}
		return nil
	})
}

// Site lookup user from key
func Site(key []byte, s *structs.Site) error {
	return Db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(siteBucket); b != nil {
			val := b.Get([]byte(key))
			site, err := gobDecodeSite(val)
			if err != nil {
				return err
			}
			*s = *site
			log.Debugf("site key %s val %v", key, s)
			log.Debugf("retrieved %s from db", s.Domain)
		}
		return nil
	})
}

// AllSites collect all items
func AllSites(sites *[]structs.Site) error {
	return Db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(siteBucket); b != nil {
			// c := b.Cursor()
			if err := b.ForEach(func(k, v []byte) error {
				log.Debugf("key=%s, value=%s\n", k, v)
				s := structs.Site{}
				if err := Site(k, &s); err != nil {
					log.Error(err)
				}
				*sites = append(*sites, s)
				return nil
			}); err != nil {
				log.Error(err)
			}
			log.Debugf("sites %v", sites)
		}
		return nil
	})
}

func gobEncodeSite(s *structs.Site) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(s)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gobDecodeSite(data []byte) (*structs.Site, error) {
	s := &structs.Site{}
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
