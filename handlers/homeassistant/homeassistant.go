package homeassistant

import (
	"github.com/vouch/vouch-proxy/handlers/common"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"net/http"
)

type Handler struct{}

// More info: https://developers.home-assistant.io/docs/en/auth_api.html
func (Handler) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) (rerr error) {
	err, _, providerToken := common.PrepareTokensAndClient(r, ptokens, false)
	if err != nil {
		return err
	}
	ptokens.PAccessToken = providerToken.Extra("access_token").(string)
	// Home assistant does not provide an API to query username, so we statically set it to "homeassistant"
	user.Username = "homeassistant"
	return nil
}
