/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package openid

import (
	"encoding/json"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"

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

func GenerateTeamsOfUser(customClaims *structs.CustomClaims, claimName string) map[string]bool {
	teamOutput := make(map[string]bool)
	if val, ok := customClaims.Claims[claimName]; ok {

		customClaimsSlice := val.([]interface{})

		for _, teamValue := range customClaimsSlice {
			team, isMyType := teamValue.(string)
			if isMyType {
				teamOutput[team] = true
			}
		}

		return teamOutput
	}
	log.Debugf("Claim %s missing from UserInfo response. Make sure you include the correct scope", claimName)
	return teamOutput
}

// GetUserInfo provider specific call to get userinfomation
func (Provider) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens, opts ...oauth2.AuthCodeOption) (rerr error) {
	client, _, err := common.PrepareTokensAndClient(r, ptokens, true, opts...)
	if err != nil {
		return err
	}
	userinfo, err := client.Get(cfg.GenOAuth.UserInfoURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("OpenID userinfo body: %s", string(data))
	if err = common.MapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	if err = json.Unmarshal(data, user); err != nil {
		log.Error(err)
		return err
	}
	user.PrepareUserData()

	if len(cfg.Cfg.TeamWhiteList) != 0 && len(cfg.GenOAuth.TeamWhiteListClaim) != 0 {
		allTeamsOfUser := GenerateTeamsOfUser(customClaims, cfg.GenOAuth.TeamWhiteListClaim)

		for _, whiteListedTeam := range cfg.Cfg.TeamWhiteList {
			if allTeamsOfUser[whiteListedTeam] {
				user.TeamMemberships = append(user.TeamMemberships, whiteListedTeam)
			}
		}
	}
	log.Debug("getUserInfoFromOAuth")
	log.Debug(user)
	return nil
}
