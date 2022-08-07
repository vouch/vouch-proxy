/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_checkCallbackConfig(t *testing.T) {
	setUp("/config/testing/handler_login_url.yml")

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"correct", "http://vouch.example.com:9090/auth", false},
		{"bad", "http://vouch.notgonna.com:9090/somewhereelse", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkCallbackConfig(tt.url); (err != nil) != tt.wantErr {
				t.Errorf("checkCallbackConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_configureOAuthWithClaims(t *testing.T) {
	setUp("/config/testing/test_config_oauth_claims.yml")
	authCodeURL, err := url.Parse(OAuthClient.AuthCodeURL("state", OAuthopts...))
	assert.Nil(t, err)
	assert.Equal(t, authCodeURL.Query().Get("claims"), `{"userinfo":{"email":{"essential":true},"email_verified":{"essential":true},"given_name":{"essential":true},"http://example.info/claims/groups":null,"nickname":null,"picture":null},"id_token":{"acr":{"values":["urn:mace:incommon:iap:silver"]},"auth_time":{"essential":true}}}`)
}

func Test_readOverlayConfig_fileVar(t *testing.T) {
	defer cleanupEnv()
	rootDir := os.Getenv(Branding.UCName + "_ROOT")
	assert.NotEmpty(t, rootDir)
	assert.NoError(t, os.Setenv(Branding.UCName+"_SECRETS_FILE", filepath.Join(rootDir, "config/testing/secret_overlay.yml")))
	setUp("config/testing/handler_login_url.yml")
	assert.Equal(t, "my client secret from overlay", OAuthClient.ClientSecret)
}

func Test_readOverlayConfig_credentialsDir(t *testing.T) {
	defer cleanupEnv()
	rootDir := os.Getenv(Branding.UCName + "_ROOT")
	assert.NotEmpty(t, rootDir)
	tempDir, err := ioutil.TempDir("", "")
	assert.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	destFileName := Branding.UCName + "_SECRETS_FILE"
	srcFileName := filepath.Join(rootDir, "config/testing/secret_overlay.yml")
	assert.NoError(t, os.Symlink(srcFileName, filepath.Join(tempDir, destFileName)))
	assert.NoError(t, os.Setenv("CREDENTIALS_DIRECTORY", tempDir))
	setUp("config/testing/handler_login_url.yml")
	assert.Equal(t, "my client secret from overlay", OAuthClient.ClientSecret)
}

func Test_readOverlayConfig_emptyCredentialsDir(t *testing.T) {
	defer cleanupEnv()
	tempDir, err := ioutil.TempDir("", "")
	assert.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	assert.NoError(t, os.Setenv("CREDENTIALS_DIRECTORY", tempDir))
	setUp("config/testing/handler_login_url.yml")
	assert.Equal(t, "", OAuthClient.ClientSecret)
}

func Test_readOverlayConfig_missingCredentialsDir(t *testing.T) {
	defer cleanupEnv()
	assert.NoError(t, os.Setenv("CREDENTIALS_DIRECTORY", "/this/doesnt/exist"))
	setUp("config/testing/handler_login_url.yml")
	assert.Equal(t, "", OAuthClient.ClientSecret)
}
