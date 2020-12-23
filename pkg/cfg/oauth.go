/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

var (
	// GenOAuth exported OAuth config variable
	// TODO: GenOAuth and OAuthClient should be combined
	GenOAuth = &Oauth{}

	// OAuthClient is the configured client which will call the provider
	// this actually carries the oauth2 client ala oauthclient.Client(oauth2.NoContext, providerToken)
	OAuthClient *oauth2.Config
	// OAuthopts authentication options
	OAuthopts oauth2.AuthCodeOption

	// Providers static strings to test against
	Providers = &OAuthProviders{
		Google:        "google",
		GitHub:        "github",
		IndieAuth:     "indieauth",
		ADFS:          "adfs",
		Azure:         "azure",
		OIDC:          "oidc",
		HomeAssistant: "homeassistant",
		OpenStax:      "openstax",
		Nextcloud:     "nextcloud",
	}
)

// OAuthProviders holds the stings for
type OAuthProviders struct {
	Google        string
	GitHub        string
	IndieAuth     string
	ADFS          string
	Azure         string
	OIDC          string
	HomeAssistant string
	OpenStax      string
	Nextcloud     string
}

type Oauth struct {
	Services []OauthConfig `mapstructure:"services" envconfig:"services"`
}

func (oa *Oauth) IterConfigs(fn func(config *OauthConfig)) {
	for i := 0; i < oa.NrOfConfigs(); i++ {
		config := oa.GetConfig(i)
		fn(config)
	}
}

func (oa *Oauth) NrOfConfigs() int {
	return len(oa.Services)
}

func (oa *Oauth) GetConfig(i int) *OauthConfig {
	return &oa.Services[i]
}

// oauth config items endoint for access
// `envconfig` tag is for env var support
// https://github.com/kelseyhightower/envconfig
type OauthConfig struct {
	Id                  string   `mapstructure:"id"`
	Provider            string   `mapstructure:"provider"`
	ClientID            string   `mapstructure:"client_id" envconfig:"client_id"`
	ClientSecret        string   `mapstructure:"client_secret" envconfig:"client_secret"`
	AuthURL             string   `mapstructure:"auth_url" envconfig:"auth_url"`
	TokenURL            string   `mapstructure:"token_url" envconfig:"token_url"`
	LogoutURL           string   `mapstructure:"end_session_endpoint"  envconfig:"end_session_endpoint"`
	RedirectURL         string   `mapstructure:"callback_url"  envconfig:"callback_url"`
	RedirectURLs        []string `mapstructure:"callback_urls"  envconfig:"callback_urls"`
	Scopes              []string `mapstructure:"scopes"`
	UserInfoURL         string   `mapstructure:"user_info_url" envconfig:"user_info_url"`
	UserTeamURL         string   `mapstructure:"user_team_url" envconfig:"user_team_url"`
	UserOrgURL          string   `mapstructure:"user_org_url" envconfig:"user_org_url"`
	PreferredDomain     string   `mapstructure:"preferredDomain"`
	CodeChallengeMethod string   `mapstructure:"code_challenge_method" envconfig:"code_challenge_method"`
}

func (config *OauthConfig) Decode(value string) error {
	options := strings.Split(value, ";")

	configType := reflect.TypeOf(config).Elem()
	configValue := reflect.ValueOf(config).Elem()
	for _, optionString := range options {
		oAuthOptions := strings.SplitN(optionString, "=", 2)
		optionsKey := oAuthOptions[0]
		optionsValue := oAuthOptions[1]

		field, found := findField(configType, optionsKey)
		if !found {
			return fmt.Errorf("Invalid key %s", optionsKey)
		}

		setField(configValue, field.Name, optionsValue)
	}

	return nil
}

// findField gets field of typ with name and tag envconfig set
func findField(typ reflect.Type, name string) (reflect.StructField, bool) {
	return typ.FieldByNameFunc(func(s string) bool {
		f, _ := typ.FieldByName(s)
		tag := f.Tag.Get("envconfig")
		return tag == strings.ToLower(name)
	})
}

// setField sets config field with name to value
func setField(cValue reflect.Value, name string, value string) {
	cField := cValue.FieldByName(name)
	cField.SetString(value)
}

func ConfigureOauth() {
	if err := UnmarshalKey("oauth", &GenOAuth); err == nil {
		GenOAuth.IterConfigs(func(config *OauthConfig) {
			config.setProviderDefaults()
		})
	}
}

func (config *OauthConfig) oauthBasicTest() error {
	if config.Provider != Providers.Google &&
		config.Provider != Providers.GitHub &&
		config.Provider != Providers.IndieAuth &&
		config.Provider != Providers.HomeAssistant &&
		config.Provider != Providers.ADFS &&
		config.Provider != Providers.Azure &&
		config.Provider != Providers.OIDC &&
		config.Provider != Providers.OpenStax &&
		config.Provider != Providers.Nextcloud {
		return errors.New("configuration error: Unknown oauth provider: " + config.Provider)
	}
	// OAuthconfig Checks
	switch {
	case config.ClientID == "":
		// everyone has a clientID
		return errors.New("configuration error: oauth.client_id not found")
	case config.Provider != Providers.IndieAuth && config.Provider != Providers.HomeAssistant && config.Provider != Providers.ADFS && config.Provider != Providers.OIDC && config.ClientSecret == "":
		// everyone except IndieAuth has a clientSecret
		// ADFS and OIDC providers also do not require this, but can have it optionally set.
		return errors.New("configuration error: oauth.client_secret not found")
	case config.Provider != Providers.Google && config.AuthURL == "":
		// everyone except IndieAuth and Google has an authURL
		return errors.New("configuration error: oauth.auth_url not found")
	case config.Provider != Providers.Google && config.Provider != Providers.IndieAuth && config.Provider != Providers.HomeAssistant && config.Provider != Providers.ADFS && config.UserInfoURL == "":
		// everyone except IndieAuth, Google and ADFS has an userInfoURL
		return errors.New("configuration error: oauth.user_info_url not found")
	case config.CodeChallengeMethod != "" && (config.CodeChallengeMethod != "plain" && config.CodeChallengeMethod != "S256"):
		return errors.New("configuration error: oauth.code_challenge_method must be either 'S256' or 'plain'")
	}

	if config.RedirectURL != "" {
		if err := checkCallbackConfig(config.RedirectURL); err != nil {
			return err
		}
	}
	if len(config.RedirectURLs) > 0 {
		for _, cb := range config.RedirectURLs {
			if err := checkCallbackConfig(cb); err != nil {
				return err
			}
		}
	}
	return nil
}

func (config *OauthConfig) setProviderDefaults() {
	if config.Provider == Providers.Google {
		config.setDefaultsGoogle()
		// setDefaultsGoogle also configures the OAuthClient
	} else if config.Provider == Providers.GitHub {
		config.setDefaultsGitHub()
		config.configureOAuthClient()
	} else if config.Provider == Providers.ADFS {
		config.setDefaultsADFS()
		config.configureOAuthClient()
	} else if config.Provider == Providers.IndieAuth || config.Provider == Providers.Azure {
		config.CodeChallengeMethod = "S256"
		config.configureOAuthClient()
	} else {
		// OIDC, OpenStax, Nextcloud
		config.configureOAuthClient()
	}
}

func (config *OauthConfig) setDefaultsGoogle() {
	log.Info("configuring Google OAuth")
	config.UserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	if len(config.Scopes) == 0 {
		// You have to select a scope from
		// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		config.Scopes = []string{"email"}
	}
	OAuthClient = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       config.Scopes,
		Endpoint:     google.Endpoint,
		RedirectURL:  config.RedirectURL,
	}
	if config.PreferredDomain != "" {
		log.Infof("setting Google OAuth preferred login domain param 'hd' to %s", config.PreferredDomain)
		OAuthopts = oauth2.SetAuthURLParam("hd", config.PreferredDomain)
	}
	config.CodeChallengeMethod = "S256"
}

func (config *OauthConfig) setDefaultsADFS() {
	log.Info("configuring ADFS OAuth")
	OAuthopts = oauth2.SetAuthURLParam("resource", config.RedirectURL) // Needed or all claims won't be included
}

func (config *OauthConfig) setDefaultsGitHub() {
	// log.Info("configuring GitHub OAuth")
	if config.AuthURL == "" {
		config.AuthURL = github.Endpoint.AuthURL
	}
	if config.TokenURL == "" {
		config.TokenURL = github.Endpoint.TokenURL
	}
	if config.UserInfoURL == "" {
		config.UserInfoURL = "https://api.github.com/user?access_token="
	}
	if config.UserTeamURL == "" {
		config.UserTeamURL = "https://api.github.com/orgs/:org_id/teams/:team_slug/memberships/:username?access_token="
	}
	if config.UserOrgURL == "" {
		config.UserOrgURL = "https://api.github.com/orgs/:org_id/members/:username?access_token="
	}
	if len(config.Scopes) == 0 {
		// https://github.com/vouch/vouch-proxy/issues/63
		// https://developer.github.com/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/
		config.Scopes = []string{"read:user"}

		if len(Cfg.TeamWhiteList) > 0 {
			config.Scopes = append(config.Scopes, "read:org")
		}
	}
	config.CodeChallengeMethod = "S256"
}

func (config *OauthConfig) configureOAuthClient() {
	log.Infof("configuring %s OAuth with Endpoint %s", config.Provider, config.AuthURL)
	OAuthClient = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
		},
		RedirectURL: config.RedirectURL,
		Scopes:      config.Scopes,
	}
}

func checkCallbackConfig(url string) error {
	if !strings.Contains(url, "/auth") {
		log.Errorf("configuration error: oauth.callback_url (%s) should almost always point at the vouch-proxy '/auth' endpoint", url)
	}

	found := false

	var uris []string
	for _, domain := range Cfg.Domains {
		uris = append(uris, domain.Uri)
	}
	for _, d := range append(uris, Cfg.Cookie.Domain) {
		if d != "" && strings.Contains(url, d) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("configuration error: oauth.callback_url (%s) must be within a configured domains where the cookie will be set: either `vouch.domains` %s or `vouch.cookie.domain` %s", url, Cfg.Domains, Cfg.Cookie.Domain)
	}

	return nil
}
