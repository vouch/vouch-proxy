package common

import (
	"encoding/json"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

var (
	log = cfg.Cfg.Logger
)

func MapClaims(claims []byte, customClaims *structs.CustomClaims) error {
	// Create a struct that contains the claims that we want to store from the config.
	var f interface{}
	err := json.Unmarshal(claims, &f)
	if err != nil {
		log.Error("Error unmarshaling claims")
		return err
	}
	m := f.(map[string]interface{})
	for k := range m {
		var found = false
		for _, e := range cfg.Cfg.Headers.Claims {
			if k == e {
				found = true
			}
		}
		if found == false {
			delete(m, k)
		}
	}
	customClaims.Claims = m
	return nil
}
