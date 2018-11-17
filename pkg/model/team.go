package model

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/vouch/vouch/pkg/structs"
	"github.com/boltdb/bolt"
)

// PutTeam - create or update a team
func PutTeam(t structs.Team) error {
	teamexists := false
	curt := &structs.Team{} // curt == current team
	err := Team([]byte(t.Name), curt)
	if err == nil {
		teamexists = true
	} else {
		log.Error(err)
	}

	return Db.Update(func(tx *bolt.Tx) error {
		if b := getBucket(tx, teamBucket); b != nil {
			t.LastUpdate = time.Now().Unix()
			if teamexists {
				log.Debugf("teamexists.. keeping time at %v, members are %v", curt.CreatedOn, curt.Members)
				t.CreatedOn = curt.CreatedOn
			} else {
				id, _ := b.NextSequence()
				t.ID = int(id)
				t.CreatedOn = t.LastUpdate
			}

			eT, err := gobEncodeTeam(&t)
			if err != nil {
				log.Error(err)
				return err
			}

			err = b.Put([]byte(t.Name), eT)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Team lookup team from key
func Team(key []byte, t *structs.Team) error {
	return Db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(teamBucket); b != nil {
			val := b.Get([]byte(key))
			team, err := gobDecodeTeam(val)
			if err != nil {
				return err
			}
			*t = *team
			log.Debugf("retrieved %s from db", t.Name)
			return nil
		}
		return fmt.Errorf("no bucket for %s", teamBucket)
	})
}

// DeleteTeam from key
func DeleteTeam(t structs.Team) error {
	return Db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(teamBucket); b != nil {
			if err := b.Delete([]byte(t.Name)); err != nil {
				return err
			}
			log.Debugf("deleted %s from db", t.Name)
			return nil
		}
		return fmt.Errorf("no bucket for %s", teamBucket)
	})
}

// AllTeams collect all items
func AllTeams(teams *[]structs.Team) error {
	return Db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(teamBucket); b != nil {
			b.ForEach(func(k, v []byte) error {
				log.Debugf("key=%s, value=%s\n", k, v)
				t := structs.Team{}
				Team(k, &t)
				*teams = append(*teams, t)
				return nil
			})
			log.Debugf("teams %v", teams)
			return nil
		}
		return fmt.Errorf("no bucket for %s", teamBucket)
	})
}

func gobEncodeTeam(t *structs.Team) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(t)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gobDecodeTeam(data []byte) (*structs.Team, error) {
	t := &structs.Team{}
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(t)
	if err != nil {
		return nil, err
	}
	return t, nil
}
