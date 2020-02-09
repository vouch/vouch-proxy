package github

import (
	"encoding/json"
	"github.com/vouch/vouch-proxy/handlers/common"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"strings"
)

type Handler struct {
	PrepareTokensAndClient func(*http.Request, *structs.PTokens, bool) (error, *http.Client, *oauth2.Token)
}

var (
	log = cfg.Cfg.Logger
)

// github
// https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/
func (me Handler) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) (rerr error) {
	err, client, ptoken := me.PrepareTokensAndClient(r, ptokens, true)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	log.Errorf("ptoken.AccessToken: %s", ptoken.AccessToken)
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
	log.Debug("getUserInfoFromGitHub ghUser")
	log.Debug(ghUser)
	log.Debug("getUserInfoFromGitHub user")
	log.Debug(user)

	ghUser.PrepareUserData()
	user.Email = ghUser.Email
	user.Name = ghUser.Name
	user.Username = ghUser.Username
	user.ID = ghUser.ID

	// user = &ghUser.User

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
				var (
					e        error
					isMember bool
				)
				if team != "" {
					e, isMember = getTeamMembershipStateFromGitHub(client, user, org, team, ptoken)
				} else {
					e, isMember = getOrgMembershipStateFromGitHub(client, user, org, ptoken)
				}
				if e != nil {
					return e
				} else {
					if isMember {
						user.TeamMemberships = append(user.TeamMemberships, orgAndTeam)
					}
				}
			} else {
				log.Warnf("Invalid org/team format in %s: must be written as <orgId>/<teamSlug>", orgAndTeam)
			}
		}
	}

	log.Debug("getUserInfoFromGitHub")
	log.Debug(user)
	return nil
}

func getOrgMembershipStateFromGitHub(client *http.Client, user *structs.User, orgId string, ptoken *oauth2.Token) (rerr error, isMember bool) {
	replacements := strings.NewReplacer(":org_id", orgId, ":username", user.Username)
	orgMembershipResp, err := client.Get(replacements.Replace(cfg.GenOAuth.UserOrgURL) + ptoken.AccessToken)
	if err != nil {
		log.Error(err)
		return err, false
	}

	if orgMembershipResp.StatusCode == 302 {
		log.Debug("Need to check public membership")
		location := orgMembershipResp.Header.Get("Location")
		if location != "" {
			orgMembershipResp, err = client.Get(location)
		}
	}

	if orgMembershipResp.StatusCode == 204 {
		return nil, true
	} else if orgMembershipResp.StatusCode == 404 {
		return nil, false
	} else {
		return nil, false
	}
}

func getTeamMembershipStateFromGitHub(client *http.Client, user *structs.User, orgId string, team string, ptoken *oauth2.Token) (rerr error, isMember bool) {
	replacements := strings.NewReplacer(":org_id", orgId, ":team_slug", team, ":username", user.Username)
	membershipStateResp, err := client.Get(replacements.Replace(cfg.GenOAuth.UserTeamURL) + ptoken.AccessToken)
	if err != nil {
		log.Error(err)
		return err, false
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
			return err, false
		}
		log.Debug("getTeamMembershipStateFromGitHub ghTeamState")
		log.Debug(ghTeamState)
		return nil, ghTeamState.State == "active"
	} else {
		return nil, false
	}
}
