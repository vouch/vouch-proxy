package common

import (
	"context"
	"encoding/json"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
	"net/http"
)

var (
	log = cfg.Cfg.Logger
)

func PrepareTokensAndClient(r *http.Request, ptokens *structs.PTokens, setpid bool) (error, *http.Client, *oauth2.Token) {
	providerToken, err := cfg.OAuthClient.Exchange(context.TODO(), r.URL.Query().Get("code"))
	if err != nil {
		return err, nil, nil
	}
	ptokens.PAccessToken = providerToken.AccessToken

	if setpid {
		if providerToken.Extra("id_token") != nil {
			// Certain providers (eg. gitea) don't provide an id_token
			// and it's not neccessary for the authentication phase
			ptokens.PIdToken = providerToken.Extra("id_token").(string)
		} else {
			log.Debugf("id_token missing - may not be supported by this provider")
		}
	}

	log.Debugf("ptokens: %+v", ptokens)

	client := cfg.OAuthClient.Client(context.TODO(), providerToken)
	return err, client, providerToken
}

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
