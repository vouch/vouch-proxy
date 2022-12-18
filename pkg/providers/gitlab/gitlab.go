package gitlab

import (
	"encoding/json"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/providers/common"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

type Provider struct{}

func (Provider) Configure() {
}

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
	data, _ := io.ReadAll(userinfo.Body)
	cfg.Logging.Logger.Infof("GitLab userinfo body: %s", string(data))
	if err = common.MapClaims(data, customClaims); err != nil {
		cfg.Logging.Logger.Error(err)
		return err
	}
	var glUser structs.GitLabUser
	if err = json.Unmarshal(data, &glUser); err != nil {
		cfg.Logging.Logger.Error(err)
		return err
	}
	glUser.PrepareUserData()
	*user = glUser.User
	return nil
}
