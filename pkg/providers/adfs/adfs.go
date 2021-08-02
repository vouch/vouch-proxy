/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package adfs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/providers/common"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

// Provider provider specific functions
type Provider struct{}

type adfsTokenRes struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int64  `json:"expires_in"` // relative seconds from now
}

var log *zap.SugaredLogger

// Configure see main.go configure()
func (Provider) Configure() {
	log = cfg.Logging.Logger
}

// GetUserInfo provider specific call to get userinfomation
// More info: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-scenarios-for-developers#supported-scenarios
func (Provider) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens, opts ...oauth2.AuthCodeOption) (rerr error) {
	code := r.URL.Query().Get("code")
	log.Debugf("code: %s", code)

	formData := url.Values{}
	formData.Set("code", code)
	formData.Set("grant_type", "authorization_code")
	formData.Set("resource", cfg.GenOAuth.RelyingPartyId)
	formData.Set("client_id", cfg.GenOAuth.ClientID)
	formData.Set("redirect_uri", cfg.GenOAuth.RedirectURL)
	if cfg.GenOAuth.ClientSecret != "" {
		formData.Set("client_secret", cfg.GenOAuth.ClientSecret)
	}
	req, err := http.NewRequest("POST", cfg.GenOAuth.TokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(formData.Encode())))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	userinfo, err := client.Do(req)

	if err != nil {
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()

	data, _ := ioutil.ReadAll(userinfo.Body)
	tokenRes := adfsTokenRes{}

	if err := json.Unmarshal(data, &tokenRes); err != nil {
		return fmt.Errorf("getUserInfoFromADFS oauth2: cannot fetch token: %+v", err)
	}

	ptokens.PAccessToken = string(tokenRes.AccessToken)
	ptokens.PIdToken = string(tokenRes.IDToken)

	s := strings.Split(tokenRes.IDToken, ".")
	if len(s) < 2 {
		return fmt.Errorf("getUserInfoFromADFS jws: invalid token received")
	}

	idToken, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return fmt.Errorf("getUserInfoFromADFS decode token: %+v", err)
	}
	log.Debugf("getUserInfoFromADFS idToken: %+v", string(idToken))

	adfsUser := structs.ADFSUser{}
	json.Unmarshal([]byte(idToken), &adfsUser)
	log.Infof("adfs adfsUser: %+v", adfsUser)
	// data contains an access token, refresh token, and id token
	// Please note that in order for custom claims to work you MUST set allatclaims in ADFS to be passed
	// https://oktotechnologies.ca/2018/08/26/adfs-openidconnect-configuration/
	if err = common.MapClaims([]byte(idToken), customClaims); err != nil {
		return err
	}
	adfsUser.PrepareUserData()
	var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if len(adfsUser.Email) == 0 {
		// If the email is blank, we will try to determine if the UPN is an email.
		if rxEmail.MatchString(adfsUser.UPN) {
			// Set the email from UPN if there is a valid email present.
			adfsUser.Email = adfsUser.UPN
		}
	}
	user.Username = adfsUser.Username
	user.Email = adfsUser.Email
	log.Debugf("User Obj: %+v", user)
	return nil
}
