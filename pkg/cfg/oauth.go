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
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

var (
	// GenOAuth exported OAuth config variable
	// TODO: GenOAuth and OAuthClient should be combined
	GenOAuth = &oauthConfig{}

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
		Alibaba:       "alibaba",
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
	Alibaba       string
}

// oauth config items endoint for access
// `envconfig` tag is for env var support
// https://github.com/kelseyhightower/envconfig
type oauthConfig struct {
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

func configureOauth() error {
	// OAuth defaults and client configuration
	return UnmarshalKey("oauth", &GenOAuth)

}

func oauthBasicTest() error {
	if GenOAuth.Provider != Providers.Google &&
		GenOAuth.Provider != Providers.GitHub &&
		GenOAuth.Provider != Providers.IndieAuth &&
		GenOAuth.Provider != Providers.HomeAssistant &&
		GenOAuth.Provider != Providers.ADFS &&
		GenOAuth.Provider != Providers.Azure &&
		GenOAuth.Provider != Providers.OIDC &&
		GenOAuth.Provider != Providers.OpenStax &&
		GenOAuth.Provider != Providers.Nextcloud &&
		GenOAuth.Provider != Providers.Alibaba {
		return errors.New("configuration error: Unknown oauth provider: " + GenOAuth.Provider)
	}
	// OAuthconfig Checks
	switch {
	case GenOAuth.ClientID == "":
		// everyone has a clientID
		return errors.New("configuration error: oauth.client_id not found")
	case GenOAuth.Provider != Providers.IndieAuth && GenOAuth.Provider != Providers.HomeAssistant && GenOAuth.Provider != Providers.ADFS && GenOAuth.Provider != Providers.OIDC && GenOAuth.ClientSecret == "":
		// everyone except IndieAuth has a clientSecret
		// ADFS and OIDC providers also do not require this, but can have it optionally set.
		return errors.New("configuration error: oauth.client_secret not found")
	case GenOAuth.Provider != Providers.Google && GenOAuth.AuthURL == "":
		// everyone except IndieAuth and Google has an authURL
		return errors.New("configuration error: oauth.auth_url not found")
	case GenOAuth.Provider != Providers.Google && GenOAuth.Provider != Providers.IndieAuth && GenOAuth.Provider != Providers.HomeAssistant && GenOAuth.Provider != Providers.ADFS && GenOAuth.UserInfoURL == "":
		// everyone except IndieAuth, Google and ADFS has an userInfoURL
		return errors.New("configuration error: oauth.user_info_url not found")
	case GenOAuth.CodeChallengeMethod != "" && (GenOAuth.CodeChallengeMethod != "plain" && GenOAuth.CodeChallengeMethod != "S256"):
		return errors.New("configuration error: oauth.code_challenge_method must be either 'S256' or 'plain'")
	}

	if GenOAuth.RedirectURL != "" {
		if err := checkCallbackConfig(GenOAuth.RedirectURL); err != nil {
			return err
		}
	}
	if len(GenOAuth.RedirectURLs) > 0 {
		for _, cb := range GenOAuth.RedirectURLs {
			if err := checkCallbackConfig(cb); err != nil {
				return err
			}
		}
	}
	return nil
}

func setProviderDefaults() {
	if GenOAuth.Provider == Providers.Google {
		setDefaultsGoogle()
		// setDefaultsGoogle also configures the OAuthClient
	} else if GenOAuth.Provider == Providers.GitHub {
		setDefaultsGitHub()
		configureOAuthClient()
	} else if GenOAuth.Provider == Providers.ADFS {
		setDefaultsADFS()
		configureOAuthClient()
	} else if GenOAuth.Provider == Providers.IndieAuth || GenOAuth.Provider == Providers.Azure {
		GenOAuth.CodeChallengeMethod = "S256"
		configureOAuthClient()
	} else {
		// OIDC, OpenStax, Nextcloud
		configureOAuthClient()
	}
}

func setDefaultsGoogle() {
	log.Info("configuring Google OAuth")
	GenOAuth.UserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	if len(GenOAuth.Scopes) == 0 {
		// You have to select a scope from
		// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		GenOAuth.Scopes = []string{"email"}
	}
	OAuthClient = &oauth2.Config{
		ClientID:     GenOAuth.ClientID,
		ClientSecret: GenOAuth.ClientSecret,
		Scopes:       GenOAuth.Scopes,
		Endpoint:     google.Endpoint,
		RedirectURL:  GenOAuth.RedirectURL,
	}
	if GenOAuth.PreferredDomain != "" {
		log.Infof("setting Google OAuth preferred login domain param 'hd' to %s", GenOAuth.PreferredDomain)
		OAuthopts = oauth2.SetAuthURLParam("hd", GenOAuth.PreferredDomain)
	}
	GenOAuth.CodeChallengeMethod = "S256"
}

func setDefaultsADFS() {
	log.Info("configuring ADFS OAuth")
	OAuthopts = oauth2.SetAuthURLParam("resource", GenOAuth.RedirectURL) // Needed or all claims won't be included
}

func setDefaultsGitHub() {
	// log.Info("configuring GitHub OAuth")
	if GenOAuth.AuthURL == "" {
		GenOAuth.AuthURL = github.Endpoint.AuthURL
	}
	if GenOAuth.TokenURL == "" {
		GenOAuth.TokenURL = github.Endpoint.TokenURL
	}
	if GenOAuth.UserInfoURL == "" {
		GenOAuth.UserInfoURL = "https://api.github.com/user?access_token="
	}
	if GenOAuth.UserTeamURL == "" {
		GenOAuth.UserTeamURL = "https://api.github.com/orgs/:org_id/teams/:team_slug/memberships/:username?access_token="
	}
	if GenOAuth.UserOrgURL == "" {
		GenOAuth.UserOrgURL = "https://api.github.com/orgs/:org_id/members/:username?access_token="
	}
	if len(GenOAuth.Scopes) == 0 {
		// https://github.com/vouch/vouch-proxy/issues/63
		// https://developer.github.com/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/
		GenOAuth.Scopes = []string{"read:user"}

		if len(Cfg.TeamWhiteList) > 0 {
			GenOAuth.Scopes = append(GenOAuth.Scopes, "read:org")
		}
	}
	GenOAuth.CodeChallengeMethod = "S256"
}

func configureOAuthClient() {
	log.Infof("configuring %s OAuth with Endpoint %s", GenOAuth.Provider, GenOAuth.AuthURL)
	OAuthClient = &oauth2.Config{
		ClientID:     GenOAuth.ClientID,
		ClientSecret: GenOAuth.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  GenOAuth.AuthURL,
			TokenURL: GenOAuth.TokenURL,
		},
		RedirectURL: GenOAuth.RedirectURL,
		Scopes:      GenOAuth.Scopes,
	}
}

func checkCallbackConfig(url string) error {
	if !strings.Contains(url, "/auth") {
		log.Errorf("configuration error: oauth.callback_url (%s) should almost always point at the vouch-proxy '/auth' endpoint", url)
	}

	found := false
	for _, d := range append(Cfg.Domains, Cfg.Cookie.Domain) {
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
