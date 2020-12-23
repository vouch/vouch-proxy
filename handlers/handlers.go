/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"fmt"
	"golang.org/x/oauth2"
	"net/http"

	"github.com/gorilla/sessions"
	"go.uber.org/zap"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/providers/adfs"
	"github.com/vouch/vouch-proxy/pkg/providers/azure"
	"github.com/vouch/vouch-proxy/pkg/providers/common"
	"github.com/vouch/vouch-proxy/pkg/providers/github"
	"github.com/vouch/vouch-proxy/pkg/providers/google"
	"github.com/vouch/vouch-proxy/pkg/providers/homeassistant"
	"github.com/vouch/vouch-proxy/pkg/providers/indieauth"
	"github.com/vouch/vouch-proxy/pkg/providers/nextcloud"
	"github.com/vouch/vouch-proxy/pkg/providers/openid"
	"github.com/vouch/vouch-proxy/pkg/providers/openstax"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

// Provider each Provider must support GetuserInfo
type Provider interface {
	Configure(config *cfg.OauthConfig)
	GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens, opts ...oauth2.AuthCodeOption) error
}

const (
	base64Bytes = 32
)

var (
	log      *zap.SugaredLogger
	fastlog  *zap.Logger
	Handlers []*Handler
)

type Handler struct {
	sessstore sessions.CookieStore
	provider  Provider
	config    *cfg.OauthConfig
}

// Configure see main.go configure()
func Configure() {
	Handlers = []*Handler{}
	cfg.GenOAuth.IterConfigs(func(config *cfg.OauthConfig) {
		Handlers = append(Handlers, Create(config))
	})

	log = cfg.Logging.Logger
	fastlog = cfg.Logging.FastLogger
	common.Configure()
}

func Create(config *cfg.OauthConfig) *Handler {

	// http://www.gorillatoolkit.org/pkg/sessions
	sessstore := sessions.NewCookieStore([]byte(cfg.Cfg.Session.Key))
	sessstore.Options.HttpOnly = cfg.Cfg.Cookie.HTTPOnly
	sessstore.Options.Secure = cfg.Cfg.Cookie.Secure
	sessstore.Options.SameSite = cookie.SameSite()
	sessstore.Options.MaxAge = 300 // give the user five minutes to log in at the IdP

	provider := GetProvider(config)
	provider.Configure(config)

	return &Handler{
		sessstore: *sessstore,
		provider:  provider,
		config:    config,
	}
}

func GetHandlerForHostname(hostname string) (*Handler, error) {

	config, err := cfg.GetConfigForHostname(hostname)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(Handlers); i++ {
		handler := Handlers[i]
		if handler.config.Id == config.Id {
			return handler, nil
		}
	}

	return nil, fmt.Errorf("No provider for service %s", config.Id)
}

func GetProvider(config *cfg.OauthConfig) Provider {
	switch config.Provider {
	case cfg.Providers.IndieAuth:
		return indieauth.Provider{}
	case cfg.Providers.ADFS:
		return adfs.Provider{}
	case cfg.Providers.Azure:
		return azure.Provider{}
	case cfg.Providers.HomeAssistant:
		return homeassistant.Provider{}
	case cfg.Providers.OpenStax:
		return openstax.Provider{}
	case cfg.Providers.Google:
		return google.Provider{}
	case cfg.Providers.GitHub:
		return github.Provider{PrepareTokensAndClient: common.PrepareTokensAndClient}
	case cfg.Providers.Nextcloud:
		return nextcloud.Provider{}
	case cfg.Providers.OIDC:
		return openid.Provider{}
	default:
		// shouldn't ever reach this since cfg checks for a properly configure `oauth.provider`
		cfg.Logging.Logger.Fatal("oauth.provider appears to be misconfigured, please check your config")
		return nil
	}
}
