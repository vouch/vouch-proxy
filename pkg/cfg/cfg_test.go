/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setUp(configFile string) {
	os.Setenv("VOUCH_CONFIG", filepath.Join(os.Getenv("VOUCH_ROOT"), configFile))
	InitForTestPurposes()
}

func TestConfigParsing(t *testing.T) {
	InitForTestPurposes()
	Configure()

	// UnmarshalKey(Branding.LCName, &cfg)
	log.Debugf("cfgPort %d", Cfg.Port)
	log.Debugf("cfgDomains %s", Cfg.Domains[0])

	assert.Equal(t, Cfg.Port, 9090)

	assert.NotEmpty(t, Cfg.JWT.MaxAge)

}
func TestConfigEnvPrecedence(t *testing.T) {
	t.Cleanup(cleanupEnv)

	envVar := "OAUTH_CLIENT_SECRET"
	envVal := "testing123"

	os.Setenv(envVar, envVal)
	// Configure()
	setUp("/config/testing/handler_login_url.yml")

	assert.Equal(t, envVal, GenOAuth.ClientSecret)

	// assert.NotEmpty(t, Cfg.JWT.MaxAge)

}

func TestConfigWithTLS(t *testing.T) {
	tests := []struct {
		name        string
		tlsKeyFile  string
		tlsCertFile string
		wantErr     bool
	}{
		{"TLSConfigOK", "/path/to/key", "/path/to/cert", false},
		{"TLSConfigKONoCert", "/path/to/key", "", true},
		{"TLSConfigKONoKey", "", "/path/to/cert", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(cleanupEnv)
			InitForTestPurposes()
			Cfg.TLS.Cert = tt.tlsCertFile
			Cfg.TLS.Key = tt.tlsKeyFile
			err := ValidateConfiguration()

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestSetGitHubDefaults(t *testing.T) {
	InitForTestPurposesWithProvider("github")
	assert.Equal(t, []string{"read:user"}, GenOAuth.Scopes)
}

func TestSetGitHubDefaultsWithTeamWhitelist(t *testing.T) {
	InitForTestPurposesWithProvider("github")
	Cfg.TeamWhiteList = append(Cfg.TeamWhiteList, "org/team")
	GenOAuth.Scopes = []string{}

	setDefaultsGitHub()
	assert.Contains(t, GenOAuth.Scopes, "read:user")
	assert.Contains(t, GenOAuth.Scopes, "read:org")
}

func TestCheckConfigWithRSA(t *testing.T) {
	setUp("config/testing/test_config_rsa.yml")
	assert.Contains(t, Cfg.JWT.PrivateKeyFile, "config/testing/rsa.key")
	assert.Contains(t, Cfg.JWT.PublicKeyFile, "config/testing/rsa.pub")
}

func Test_claimToHeader(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    string
		wantErr bool
	}{
		{"remove http://", "http://test.example.com", Cfg.Headers.ClaimHeader + "Test-Example-Com", false},
		{"remove https://", "https://test.example.com", Cfg.Headers.ClaimHeader + "Test-Example-Com", false},
		{"auth0 fix https://", "https://test.auth0.com/user", Cfg.Headers.ClaimHeader + "Test-Auth0-Com-User", false},
		{"cognito user:groups", "user:groups", Cfg.Headers.ClaimHeader + "User-Groups", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := claimToHeader(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("claimToHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("claimToHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_configureFromEnvCfg(t *testing.T) {
	t.Cleanup(cleanupEnv)
	// each of these env vars holds a..
	// string
	senv := []string{"VOUCH_LISTEN", "VOUCH_JWT_ISSUER", "VOUCH_JWT_SECRET", "VOUCH_HEADERS_JWT", "VOUCH_HEADERS_SUB",
		"VOUCH_HEADERS_USER", "VOUCH_HEADERS_QUERYSTRING", "VOUCH_HEADERS_REDIRECT", "VOUCH_HEADERS_SUCCESS", "VOUCH_HEADERS_ERROR",
		"VOUCH_HEADERS_CLAIMHEADER", "VOUCH_HEADERS_ACCESSTOKEN", "VOUCH_HEADERS_IDTOKEN", "VOUCH_COOKIE_NAME", "VOUCH_COOKIE_DOMAIN",
		"VOUCH_COOKIE_SAMESITE", "VOUCH_TESTURL", "VOUCH_SESSION_NAME", "VOUCH_SESSION_KEY", "VOUCH_DOCUMENT_ROOT", "VOUCH_SOCKETGROUP"}
	// array of strings
	saenv := []string{"VOUCH_DOMAINS", "VOUCH_WHITELIST", "VOUCH_TEAMWHITELIST", "VOUCH_HEADERS_CLAIMS", "VOUCH_TESTURLS", "VOUCH_POST_LOGOUT_REDIRECT_URIS"}
	// int
	ienv := []string{"VOUCH_PORT", "VOUCH_JWT_MAXAGE", "VOUCH_COOKIE_MAXAGE", "VOUCH_SESSION_MAXAGE", "VOUCH_WRITETIMEOUT", "VOUCH_READTIMEOUT",
		"VOUCH_IDLETIMEOUT", "VOUCH_SOCKETMODE"}
	// bool
	benv := []string{"VOUCH_ALLOWALLUSERS", "VOUCH_PUBLICACCESS", "VOUCH_JWT_COMPRESS", "VOUCH_COOKIE_SECURE",
		"VOUCH_COOKIE_HTTPONLY", "VOUCH_TESTING"}

	// populate environmental variables
	svalue := "svalue"
	for _, v := range senv {
		os.Setenv(v, svalue)
	}
	// "VOUCH_LOGLEVEL" is special since logging is occurring during these tests, needs to be an actual level
	os.Setenv("VOUCH_LOGLEVEL", "debug")

	savalue := []string{"arrayone", "arraytwo", "arraythree"}

	for _, v := range saenv {
		os.Setenv(v, strings.Join(savalue, ","))
		t.Logf("savalue: %s", savalue)
	}
	ivalue := 1234
	for _, v := range ienv {
		os.Setenv(v, fmt.Sprint(ivalue))
	}
	bvalue := false
	for _, v := range benv {
		os.Setenv(v, fmt.Sprint(bvalue))
	}

	// run the thing
	configureFromEnv()
	scfg := []string{Cfg.Listen, Cfg.JWT.Issuer, Cfg.JWT.Secret, Cfg.Headers.JWT, Cfg.Headers.Sub,
		Cfg.Headers.User, Cfg.Headers.QueryString, Cfg.Headers.Redirect, Cfg.Headers.Success, Cfg.Headers.Error,
		Cfg.Headers.ClaimHeader, Cfg.Headers.AccessToken, Cfg.Headers.IDToken, Cfg.Cookie.Name, Cfg.Cookie.Domain,
		Cfg.Cookie.SameSite, Cfg.TestURL, Cfg.Session.Name, Cfg.Session.Key, Cfg.DocumentRoot, Cfg.SocketGroup,
	}

	sacfg := [][]string{Cfg.Domains, Cfg.WhiteList, Cfg.TeamWhiteList, Cfg.Headers.Claims, Cfg.TestURLs, Cfg.LogoutRedirectURLs}
	icfg := []int{Cfg.Port, Cfg.JWT.MaxAge, Cfg.Cookie.MaxAge, Cfg.WriteTimeout, Cfg.ReadTimeout, Cfg.IdleTimeout, Cfg.SocketMode}
	bcfg := []bool{Cfg.AllowAllUsers, Cfg.PublicAccess, Cfg.JWT.Compress,
		Cfg.Cookie.Secure,
		Cfg.Cookie.HTTPOnly,
		Cfg.Testing,
	}

	tests := []struct {
		name string
	}{
		{"Cfg struct field should be populated from env var"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, Cfg.LogLevel, "debug", "Cfg.LogLevel is not debug")
			for i, v := range scfg {
				assert.Equal(t, svalue, v, fmt.Sprintf("%d: v is %s not %s", i, v, svalue))
			}
			for _, v := range sacfg {
				assert.Equal(t, savalue, v, "v is %+s not %+s", v, savalue)
			}
			for _, v := range icfg {
				assert.Equal(t, ivalue, v, "v is %+s not %+s", v, ivalue)
			}
			for _, v := range bcfg {
				assert.Equal(t, bvalue, v, "v is %+s not %+s", v, bvalue)
			}
		})
	}

}

func Test_configureFromEnvOAuth(t *testing.T) {
	t.Cleanup(cleanupEnv)

	// each of these env vars holds a..
	// string
	// get all the values
	senv := []string{
		"OAUTH_PROVIDER", "OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET", "OAUTH_AUTH_URL", "OAUTH_TOKEN_URL",
		"OAUTH_END_SESSION_ENDPOINT", "OAUTH_CALLBACK_URL", "OAUTH_USER_INFO_URL", "OAUTH_USER_TEAM_URL", "OAUTH_USER_ORG_URL",
		"OAUTH_PREFERREDDOMAIN", "OAUTH_RELYING_PARTY_ID",
	}
	// array of strings
	saenv := []string{"OAUTH_CALLBACK_URLS", "OAUTH_SCOPES"}

	// populate environmental variables
	svalue := "svalue"
	for _, v := range senv {
		os.Setenv(v, svalue)
	}
	savalue := []string{"arrayone", "arraytwo", "arraythree"}
	for _, v := range saenv {
		os.Setenv(v, strings.Join(savalue, ","))
		t.Logf("savalue: %s", savalue)
	}

	// run the thing
	configureFromEnv()

	scfg := []string{
		GenOAuth.Provider,
		GenOAuth.ClientID,
		GenOAuth.ClientSecret,
		GenOAuth.AuthURL,
		GenOAuth.TokenURL,
		GenOAuth.LogoutURL,
		GenOAuth.RedirectURL,
		GenOAuth.UserInfoURL,
		GenOAuth.UserTeamURL,
		GenOAuth.UserOrgURL,
		GenOAuth.PreferredDomain,
		GenOAuth.RelyingPartyId,
	}
	sacfg := [][]string{
		GenOAuth.RedirectURLs,
		GenOAuth.Scopes,
	}

	tests := []struct {
		name string
	}{
		{"OAuth struct field should be populated from env var"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, v := range scfg {
				assert.Equal(t, svalue, v, fmt.Sprintf("%d: v is %s not %s", i, v, svalue))
			}
			for i, v := range sacfg {
				assert.Equal(t, savalue, v, fmt.Sprintf("%d: v is %s not %s", i, v, savalue))
			}
		})
	}
}

func cleanupEnv() {
	os.Clearenv()
	os.Setenv(Branding.UCName+"_ROOT", RootDir)
	Cfg = &Config{}
	GenOAuth = &oauthConfig{}
}
