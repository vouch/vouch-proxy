package openstax

import (
	"encoding/json"
	"github.com/vouch/vouch-proxy/handlers/common"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
)

var (
	log = cfg.Cfg.Logger
)

func GetUserInfoFromOpenStax(client *http.Client, user *structs.User, customClaims *structs.CustomClaims, ptoken *oauth2.Token) (rerr error) {
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
