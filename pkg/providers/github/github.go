/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package github

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/providers/common"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Provider provider specific functions
type Provider struct {
	PrepareTokensAndClient func(r *http.Request, ptokens *structs.PTokens, setProviderToken bool, opts ...oauth2.AuthCodeOption) (*http.Client, *oauth2.Token, error)
}

var log *zap.SugaredLogger

// Configure see main.go configure()
func (Provider) Configure() {
	log = cfg.Logging.Logger
}

// GetUserInfo github user info, calls github api for org and teams
// https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/
func (me Provider) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens, opts ...oauth2.AuthCodeOption) (rerr error) {
	client, ptoken, err := me.PrepareTokensAndClient(r, ptokens, true)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	log.Debugf("ptoken.AccessToken: %s", ptoken.AccessToken)
	userinfo, err := client.Get(cfg.GenOAuth.UserInfoURL + ptoken.AccessToken)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()
	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("github userinfo body: %s", string(data))
	if err = common.MapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	ghUser := structs.GitHubUser{}
	if err = json.Unmarshal(data, &ghUser); err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("getUserInfoFromGitHub ghUser %+v", ghUser)

	ghUser.PrepareUserData()
	*user = ghUser.User

	toOrgAndTeam := func(orgAndTeam string) (string, string) {
		split := strings.Split(orgAndTeam, "/")
		if len(split) == 1 {
			// only organization given
			return orgAndTeam, ""
		} else if len(split) == 2 {
			return split[0], split[1]
		} else {
			return "", ""
		}
	}

	if len(cfg.Cfg.TeamWhiteList) != 0 {
		for _, orgAndTeam := range cfg.Cfg.TeamWhiteList {
			org, team := toOrgAndTeam(orgAndTeam)
			if org != "" {
				log.Info(org)
				var err error
				isMember := false
				if team != "" {
					isMember, err = getTeamMembershipStateFromGitHub(client, user, org, team, ptoken)
				} else {
					isMember, err = getOrgMembershipStateFromGitHub(client, user, org, ptoken)
				}
				if err != nil {
					return err
				}
				if isMember {
					user.TeamMemberships = append(user.TeamMemberships, orgAndTeam)
				}

			} else {
				log.Warnf("Invalid org/team format in %s: must be written as <orgId>/<teamSlug>", orgAndTeam)
			}
		}
	}

	log.Debugf("getUserInfoFromGitHub user: %+v", user)
	return nil
}

func getOrgMembershipStateFromGitHub(client *http.Client, user *structs.User, orgID string, ptoken *oauth2.Token) (isMember bool, rerr error) {
	replacements := strings.NewReplacer(":org_id", orgID, ":username", user.Username)
	orgMembershipResp, err := client.Get(replacements.Replace(cfg.GenOAuth.UserOrgURL) + ptoken.AccessToken)
	if err != nil {
		log.Error(err)
		return false, err
	}

	if orgMembershipResp.StatusCode == 302 {
		log.Debug("Need to check public membership")
		location := orgMembershipResp.Header.Get("Location")
		if location != "" {
			orgMembershipResp, err = client.Get(location)
		}
	}

	if orgMembershipResp.StatusCode == 204 {
		log.Debug("getOrgMembershipStateFromGitHub isMember: true")
		return true, nil
	} else if orgMembershipResp.StatusCode == 404 {
		log.Debug("getOrgMembershipStateFromGitHub isMember: false")
		return false, nil
	} else {
		log.Errorf("getOrgMembershipStateFromGitHub: unexpected status code %d", orgMembershipResp.StatusCode)
		return false, errors.New("Unexpected response status " + orgMembershipResp.Status)
	}
}

func getTeamMembershipStateFromGitHub(client *http.Client, user *structs.User, orgID string, team string, ptoken *oauth2.Token) (isMember bool, rerr error) {
	replacements := strings.NewReplacer(":org_id", orgID, ":team_slug", team, ":username", user.Username)
	membershipStateResp, err := client.Get(replacements.Replace(cfg.GenOAuth.UserTeamURL) + ptoken.AccessToken)
	if err != nil {
		log.Error(err)
		return false, err
	}
	defer func() {
		if err := membershipStateResp.Body.Close(); err != nil {
			rerr = err
		}
	}()
	if membershipStateResp.StatusCode == 200 {
		data, _ := ioutil.ReadAll(membershipStateResp.Body)
		log.Infof("github team membership body: ", string(data))
		ghTeamState := structs.GitHubTeamMembershipState{}
		if err = json.Unmarshal(data, &ghTeamState); err != nil {
			log.Error(err)
			return false, err
		}
		log.Debugf("getTeamMembershipStateFromGitHub ghTeamState %s", ghTeamState)
		return ghTeamState.State == "active", nil
	} else if membershipStateResp.StatusCode == 404 {
		log.Debug("getTeamMembershipStateFromGitHub isMember: false")
		return false, err
	} else {
		log.Errorf("getTeamMembershipStateFromGitHub: unexpected status code %d", membershipStateResp.StatusCode)
		return false, errors.New("Unexpected response status " + membershipStateResp.Status)
	}
}
