/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package homeassistant

import (
	"encoding/json"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/gorilla/websocket"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/providers/common"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"go.uber.org/zap"
)

// Provider provider specific functions
type Provider struct{}

var log *zap.SugaredLogger

// Configure see main.go configure()
func (Provider) Configure() {
	log = cfg.Logging.Logger
}

type AuthMessage struct {
	Type  string `json:"type"`
	Token string `json:"access_token"`
}

type AuthResponse struct {
	Type string `json:"type"`
}

type RequestMessage struct {
	Id   int    `json:"id"`
	Type string `json:"type"`
}

type ResponseMessage struct {
	Id      int                       `json:"id"`
	Success bool                      `json:"success"`
	Result  structs.HomeAssistantUser `json:"result"`
}

// GetUserInfo provider specific call to get userinfomation
// More info: https://github.com/home-assistant/core/blob/5280291f98db41b6edd822a6b2fe6df4dea3df6a/homeassistant/components/auth/__init__.py#L484
// Websocket API info: https://developers.home-assistant.io/docs/api/websocket
func (Provider) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens, opts ...oauth2.AuthCodeOption) (rerr error) {
	_, providerToken, err := common.PrepareTokensAndClient(r, ptokens, false, opts...)
	if err != nil {
		return err
	}
	ptokens.PAccessToken = providerToken.Extra("access_token").(string)

	client, _, err := websocket.DefaultDialer.Dial(cfg.GenOAuth.UserInfoURL, nil)
	if err != nil {
		log.Errorf("error dialing HA websocket: %v", err)
		return err
	}
	defer client.Close()

	_, _, err = client.ReadMessage()
	if err != nil {
		log.Errorf("error reading HA init message: %v", err)
		return err
	}

	authMessage := AuthMessage{
		Type:  "auth",
		Token: ptokens.PAccessToken,
	}
	if err := client.WriteJSON(authMessage); err != nil {
		return err
	}
	_, authResponseData, err := client.ReadMessage()
	if err != nil {
		return err
	}
	var authResponse AuthResponse
	if err := json.Unmarshal(authResponseData, &authResponse); err != nil {
		return err
	}
	if authResponse.Type != "auth_ok" {
		log.Errorf("error authenticating with HA: %s", authResponseData)
		return err
	}

	requestMessage := RequestMessage{
		Id:   10, // Can be any number but must be increased on each request
		Type: "auth/current_user",
	}
	if err := client.WriteJSON(requestMessage); err != nil {
		return err
	}
	_, responseMessage, err := client.ReadMessage()
	if err != nil {
		return err
	}
	log.Infof("HA userinfo body: %s", string(responseMessage))
	if err = common.MapClaims(responseMessage, customClaims); err != nil {
		log.Error(err)
		return err
	}
	var data ResponseMessage
	if err := json.Unmarshal(responseMessage, &data); err != nil {
		return err
	}
	if !data.Success {
		log.Errorf("error getting user info from HA: %s", responseMessage)
		return err
	}
	data.Result.PrepareUserData()
	user.Username = data.Result.Username
	return nil
}
