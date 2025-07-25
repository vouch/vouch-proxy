/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package discord

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"

	"go.uber.org/zap"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/providers/common"
	"github.com/vouch/vouch-proxy/pkg/structs"
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
	data, err := io.ReadAll(userinfo.Body)
	if err != nil {
		return err
	}
	log.Infof("Discord userinfo body: %s", string(data))
	if err = common.MapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	dUser := structs.DiscordUser{}
	if err = json.Unmarshal(data, &dUser); err != nil {
		log.Error(err)
		return err
	}

	// If the provider is configured to use IDs, the ID is copied to PreparedUsername.
	if cfg.GenOAuth.DiscordUseIDs {
		user.Username = dUser.Id
	} else {
		user.Username = dUser.Username

		// If the Discriminator is present that is appended to the Username in the format "Username#Discriminator"
		// to match the old format of Discord usernames
		// Previous format which is being phased out: https://support.discord.com/hc/en-us/articles/4407571667351-Law-Enforcement-Guidelines Subheading "How to find usernames and discriminators"
		// Details about the new username requirements: https://support.discord.com/hc/en-us/articles/12620128861463
		if dUser.Discriminator != "0" {
			user.Username = fmt.Sprintf("%s#%s", dUser.Username, dUser.Discriminator)
		}
	}
	user.Email = dUser.Email

	return nil
}
