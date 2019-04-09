package cfg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type oidcDiscoveryJSON struct {
	Issuer          string   `json:"issuer"`
	AuthURL         string   `json:"authorization_endpoint"`
	TokenURL        string   `json:"token_endpoint"`
	UserInfoURL     string   `json:"userinfo_endpoint"`
	ScopesSupported []string `json:"scopes_supported"`
}

func configureOAuth() {
	// OAuth defaults and client configuration
	if err := UnmarshalKey("oauth", &GenOAuth); err != nil {
		log.Fatalf("error configuring oauth %s", err.Error())
	}
	if GenOAuth.Provider == Providers.Google {
		setDefaultsGoogle()
		// setDefaultsGoogle also configures the OAuthClient
	} else if GenOAuth.Provider == Providers.GitHub {
		setDefaultsGitHub()
		configureOAuthClient()
	} else if GenOAuth.Provider == Providers.ADFS {
		setDefaultsADFS()
		configureOAuthClient()
	} else if GenOAuth.Provider == Providers.OIDC && GenOAuth.ProviderURL != "" {
		if err := setOAuthDefaultsOIDCDiscovery(); err != nil {
			log.Errorf("error setting endpoints from OIDC Discovery: %s", err.Error())
		}
	} else {
		configureOAuthClient()
	}

}

// retrieve JSON from provider's /.well-known/openid-configuration and configure endpoints
func setOAuthDefaultsOIDCDiscovery() error {
	// func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	wellKnownURL := strings.TrimSuffix(GenOAuth.ProviderURL, "/") + "/.well-known/openid-configuration"
	log.Infof("configuring oauth enpoints via OIDC Discovery from %s", wellKnownURL)
	req, err := http.NewRequest("GET", wellKnownURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("oidc: unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, body)
	}

	var oidcD oidcDiscoveryJSON
	err = json.Unmarshal(body, &oidcD)
	if err != nil {
		return fmt.Errorf("oidc: couldn't read json from provider: %v", err)
	}

	if GenOAuth.ProviderURL != oidcD.Issuer {
		return fmt.Errorf("oidc: issuers did not match, wanted: %q got: %q", GenOAuth.ProviderURL, oidcD.Issuer)
	}

	// SUCCESS!!
	// set the retrieved items

	GenOAuth.AuthURL = oidcD.AuthURL
	GenOAuth.TokenURL = oidcD.TokenURL
	GenOAuth.UserInfoURL = oidcD.UserInfoURL

	if len(oidcD.ScopesSupported) > 0 {
		GenOAuth.Scopes = oidcD.ScopesSupported
	} else {
		GenOAuth.Scopes = []string{"openid"}
	}

	log.Debugf("set oauth.AuthURL %s", GenOAuth.AuthURL)
	log.Debugf("set oauth.TokenURL %s", GenOAuth.TokenURL)
	log.Debugf("set oauth.UserInfoURL %s", GenOAuth.UserInfoURL)
	log.Debugf("set oauth.Scopes %s", GenOAuth.Scopes)

	return nil
}

func setDefaultsGoogle() {
	log.Info("configuring Google OAuth")
	GenOAuth.UserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	OAuthClient = &oauth2.Config{
		ClientID:     GenOAuth.ClientID,
		ClientSecret: GenOAuth.ClientSecret,
		Scopes: []string{
			// You have to select a scope from
			// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	if GenOAuth.PreferredDomain != "" {
		log.Infof("setting Google OAuth preferred login domain param 'hd' to %s", GenOAuth.PreferredDomain)
		OAuthopts = oauth2.SetAuthURLParam("hd", GenOAuth.PreferredDomain)
	}
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
	if len(GenOAuth.Scopes) == 0 {
		// https://github.com/vouch/vouch-proxy/issues/63
		// https://developer.github.com/apps/building-oauth-apps/understanding-scopes-for-oauth-apps/
		GenOAuth.Scopes = []string{"read:user"}
	}
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
