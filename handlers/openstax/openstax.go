package openstax

import (
	"encoding/json"
	"github.com/vouch/vouch-proxy/handlers/common"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"io/ioutil"
	"net/http"
)

// Provider provider specific functions
type Provider struct{}

var (
	log = cfg.Cfg.Logger
)

// GetUserInfo provider specific call to get userinfomation
func (Provider) GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) (rerr error) {
	client, _, err := common.PrepareTokensAndClient(r, ptokens, false)
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
	log.Infof("OpenStax userinfo body: %s", string(data))
	if err = common.MapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	oxUser := structs.OpenStaxUser{}
	if err = json.Unmarshal(data, &oxUser); err != nil {
		log.Error(err)
		return err
	}

	oxUser.PrepareUserData()
	user.Email = oxUser.Email
	user.Name = oxUser.Name
	user.Username = oxUser.Username
	user.ID = oxUser.ID
	user.PrepareUserData()
	return nil
}
