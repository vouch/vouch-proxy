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

func (oac *OauthConfig) Decode(value string) error {
	options := strings.Split(value, ";")

	oacObject := reflect.ValueOf(oac)
	oacType := reflect.TypeOf(oac)
	for _, optionString := range options {
		oAuthOptions := strings.SplitN(optionString, "=", 2)

		tField, found := oacType.Elem().FieldByNameFunc(func(s string) bool {
			f, _ := oacType.Elem().FieldByName(s)
			tag := f.Tag.Get("envconfig")
			return tag == strings.ToLower(oAuthOptions[0])
		})
		if !found {
			return fmt.Errorf("Invalid key %s", oAuthOptions[0])
		}

		oField := oacObject.Elem().FieldByName(tField.Name)
		oField.SetString(oAuthOptions[1])
	}

	return nil
}

func ConfigureOauth() {
	if err := UnmarshalKey("oauth", &GenOAuth); err == nil {
		for i := 0; i < len((*GenOAuth).Services); i++ {
			setProviderDefaults(&(*GenOAuth).Services[i])
		}
	}
}

func oauthBasicTest(service OauthConfig) error {
	if service.Provider != Providers.Google &&
		service.Provider != Providers.GitHub &&
		service.Provider != Providers.IndieAuth &&
		service.Provider != Providers.HomeAssistant &&
		service.Provider != Providers.ADFS &&
		service.Provider != Providers.Azure &&
		service.Provider != Providers.OIDC &&
		service.Provider != Providers.OpenStax &&
		service.Provider != Providers.Nextcloud {
		return errors.New("configuration error: Unknown oauth provider: " + service.Provider)
	}
	// OAuthconfig Checks
	switch {
	case service.ClientID == "":
		// everyone has a clientID
		return errors.New("configuration error: oauth.client_id not found")
	case service.Provider != Providers.IndieAuth && service.Provider != Providers.HomeAssistant && service.Provider != Providers.ADFS && service.Provider != Providers.OIDC && service.ClientSecret == "":
		// everyone except IndieAuth has a clientSecret
		// ADFS and OIDC providers also do not require this, but can have it optionally set.
		return errors.New("configuration error: oauth.client_secret not found")
	case service.Provider != Providers.Google && service.AuthURL == "":
		// everyone except IndieAuth and Google has an authURL
		return errors.New("configuration error: oauth.auth_url not found")
	case service.Provider != Providers.Google && service.Provider != Providers.IndieAuth && service.Provider != Providers.HomeAssistant && service.Provider != Providers.ADFS && service.UserInfoURL == "":
		// everyone except IndieAuth, Google and ADFS has an userInfoURL
		return errors.New("configuration error: oauth.user_info_url not found")
	case service.CodeChallengeMethod != "" && (service.CodeChallengeMethod != "plain" && service.CodeChallengeMethod != "S256"):
		return errors.New("configuration error: oauth.code_challenge_method must be either 'S256' or 'plain'")
	}

	if service.RedirectURL != "" {
		if err := checkCallbackConfig(service.RedirectURL); err != nil {
			return err
		}
	}
	if len(service.RedirectURLs) > 0 {
		for _, cb := range service.RedirectURLs {
			if err := checkCallbackConfig(cb); err != nil {
				return err
			}
		}
	}
	return nil
}

func setProviderDefaults(service *OauthConfig) {
	if service.Provider == Providers.Google {
		setDefaultsGoogle(service)
		// setDefaultsGoogle also configures the OAuthClient
	} else if service.Provider == Providers.GitHub {
		setDefaultsGitHub(service)
		configureOAuthClient(service)
	} else if service.Provider == Providers.ADFS {
		setDefaultsADFS(service)
		configureOAuthClient(service)
	} else if service.Provider == Providers.IndieAuth || service.Provider == Providers.Azure {
		service.CodeChallengeMethod = "S256"
		configureOAuthClient(service)
	} else {
		// OIDC, OpenStax, Nextcloud
		configureOAuthClient(service)
	}
}

func setDefaultsGoogle(service *OauthConfig) {
	log.Info("configuring Google OAuth")
	service.UserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	if len(service.Scopes) == 0 {
		// You have to select a scope from
		// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		service.Scopes = []string{"email"}
	}
	OAuthClient = &oauth2.Config{
		ClientID:     service.ClientID,
		ClientSecret: service.ClientSecret,
		Scopes:       service.Scopes,
		Endpoint:     google.Endpoint,
		RedirectURL:  service.RedirectURL,
	}
	if service.PreferredDomain != "" {
		log.Infof("setting Google OAuth preferred login domain param 'hd' to %s", service.PreferredDomain)
		OAuthopts = oauth2.SetAuthURLParam("hd", service.PreferredDomain)
	}
	service.CodeChallengeMethod = "S256"
}

func setDefaultsADFS(service *OauthConfig) {
	log.Info("configuring ADFS OAuth")
	OAuthopts = oauth2.SetAuthURLParam("resource", service.RedirectURL) // Needed or all claims won't be included
}

func setDefaultsGitHub(service *OauthConfig) {
	// log.Info("configuring GitHub OAuth")
	if service.AuthURL == "" {
		service.AuthURL = github.Endpoint.AuthURL
	}
	if service.TokenURL == "" {
		service.TokenURL = github.Endpoint.TokenURL
	}
	if service.UserInfoURL == "" {
		service.UserInfoURL = "https://api.github.com/user?access_token="
	}
	if service.UserTeamURL == "" {
		service.UserTeamURL = "https://api.github.com/orgs/:org_id/teams/:team_slug/memberships/:username?access_token="
	}
	if service.UserOrgURL == "" {
		service.UserOrgURL = "https://api.github.com/orgs/:org_id/members/:username?access_token="
	}
	if len(service.Scopes) == 0 {
		// https://github.com/vouch/vouch-proxy/issues/63
		// https://developer.github.com/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/
		service.Scopes = []string{"read:user"}

		if len(Cfg.TeamWhiteList) > 0 {
			service.Scopes = append(service.Scopes, "read:org")
		}
	}
	service.CodeChallengeMethod = "S256"
}

func configureOAuthClient(service *OauthConfig) {
	log.Infof("configuring %s OAuth with Endpoint %s", service.Provider, service.AuthURL)
	OAuthClient = &oauth2.Config{
		ClientID:     service.ClientID,
		ClientSecret: service.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  service.AuthURL,
			TokenURL: service.TokenURL,
		},
		RedirectURL: service.RedirectURL,
		Scopes:      service.Scopes,
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
