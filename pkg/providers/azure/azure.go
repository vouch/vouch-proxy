/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package azure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"strings"

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

// GetUserInfo provider specific call to get userinfomation
func (Provider) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens, opts ...oauth2.AuthCodeOption) (rerr error) {
	_, _, err := common.PrepareTokensAndClient(r, ptokens, true, opts...)
	if err != nil {
		return err
	}

	// For Azure AD, there is very little information in the /userinfo response.
	// Since we can get everything we currently need from the access token, we are
	// just going to extract user info and custom claims from there.
	azureUser := structs.AzureUser{}

	var tokenParts []string

	if cfg.GenOAuth.AzureToken == "access_token" {
		tokenParts = strings.Split(ptokens.PAccessToken, ".")
	} else if cfg.GenOAuth.AzureToken == "id_token" {
		tokenParts = strings.Split(ptokens.PIdToken, ".")
	} else {
		err = fmt.Errorf("Azure Token not access_token or id_token")
		log.Error(err)
		return err
	}

	if len(tokenParts) < 2 {
		err = fmt.Errorf("azure GetUserInfo: invalid token received; not enough parts")
		log.Error(err)
		return err
	}

	tokenBytes, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		err = fmt.Errorf("azure GetUserInfo: decoding token failed: %+v", err)
		log.Error(err)
		return err
	}

	if err = common.MapClaims(tokenBytes, customClaims); err != nil {
		log.Error(err)
		return err
	}

	log.Debugf("azure GetUserInfo: getting user info from token: %+v", string(tokenBytes))
	if err = json.Unmarshal(tokenBytes, &azureUser); err != nil {
		err = fmt.Errorf("azure getUserInfoFromTokens: unpacking token into AzureUser failed: %+v", err)
		log.Error(err)
		return err
	}

	azureUser.PrepareUserData()

	user.Username = azureUser.Username
	user.Name = azureUser.Name
	user.Email = azureUser.Email
	log.Infof("azure GetUserInfo: User: %+v", user)

	return nil
}
