/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that 
can be found in the LICENSE file. Software distributed under The 
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/vouch/vouch-proxy/handlers/adfs"
	"github.com/vouch/vouch-proxy/handlers/common"
	"github.com/vouch/vouch-proxy/handlers/github"
	"github.com/vouch/vouch-proxy/handlers/google"
	"github.com/vouch/vouch-proxy/handlers/homeassistant"
	"github.com/vouch/vouch-proxy/handlers/indieauth"
	"github.com/vouch/vouch-proxy/handlers/nextcloud"
	"github.com/vouch/vouch-proxy/handlers/openid"
	"github.com/vouch/vouch-proxy/handlers/openstax"

	"go.uber.org/zap"

	"github.com/gorilla/sessions"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

// Index variables passed to index.tmpl
type Index struct {
	Msg      string
	TestURLs []string
	Testing  bool
}

// Provider each Provider must support GetuserInfo
type Provider interface {
	Configure()
	GetUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) error
}

const (
	base64Bytes = 32
)

var (
	indexTemplate *template.Template
	sessstore     *sessions.CookieStore
	log           *zap.SugaredLogger
	fastlog       *zap.Logger
	provider      Provider
)

// Configure see main.go configure()
func Configure() {
	log = cfg.Logging.Logger
	fastlog = cfg.Logging.FastLogger
	// http://www.gorillatoolkit.org/pkg/sessions
	sessstore = sessions.NewCookieStore([]byte(cfg.Cfg.Session.Key))
	sessstore.Options.HttpOnly = cfg.Cfg.Cookie.HTTPOnly
	sessstore.Options.Secure = cfg.Cfg.Cookie.Secure
	sessstore.Options.SameSite = cookie.SameSite()

	log.Debugf("handlers.Configure() attempting to parse templates with cfg.RootDir: %s", cfg.RootDir)
	indexTemplate = template.Must(template.ParseFiles(filepath.Join(cfg.RootDir, "templates/index.tmpl")))

	provider = getProvider()
	provider.Configure()
}

func getProvider() Provider {
	switch cfg.GenOAuth.Provider {
	case cfg.Providers.IndieAuth:
		return indieauth.Provider{}
	case cfg.Providers.ADFS:
		return adfs.Provider{}
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
		log.Fatal("oauth.provider appears to be misconfigured, please check your config")
		return nil
	}
}
