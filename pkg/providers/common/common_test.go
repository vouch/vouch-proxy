/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package common

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

func setUpOAuthClientForRequestTest(t *testing.T) {
	t.Helper()

	previousCfg := cfg.Cfg
	previousOAuthClient := cfg.OAuthClient
	previousRedirectURLs := cfg.GenOAuth.RedirectURLs
	previousLog := log

	cfg.Cfg = &cfg.Config{Domains: []string{"example.com", "other.com"}}
	cfg.OAuthClient = &oauth2.Config{RedirectURL: "https://startup.example.com/auth"}
	cfg.GenOAuth.RedirectURLs = []string{
		"https://vouch.example.com/auth",
		"https://vouch.other.com/auth",
	}
	log = zap.NewNop().Sugar()
	domains.Configure()

	t.Cleanup(func() {
		cfg.Cfg = previousCfg
		cfg.OAuthClient = previousOAuthClient
		cfg.GenOAuth.RedirectURLs = previousRedirectURLs
		log = previousLog
	})
}

func TestOAuthClientForRequest(t *testing.T) {
	setUpOAuthClientForRequestTest(t)

	firstRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	firstRequest.Host = "vouch.example.com"
	firstClient := OAuthClientForRequest(firstRequest)
	assert.Equal(t, "https://vouch.example.com/auth", firstClient.RedirectURL)

	secondRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	secondRequest.Host = "vouch.other.com"
	secondClient := OAuthClientForRequest(secondRequest)
	assert.Equal(t, "https://vouch.other.com/auth", secondClient.RedirectURL)

	assert.Equal(t, "https://vouch.example.com/auth", firstClient.RedirectURL)
	assert.Equal(t, "https://startup.example.com/auth", cfg.OAuthClient.RedirectURL)
}

func TestOAuthClientForRequestFallsBackToStartupRedirectURL(t *testing.T) {
	setUpOAuthClientForRequestTest(t)

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	for _, host := range []string{"", "vouch.unknown.test"} {
		request.Host = host
		assert.Equal(t, cfg.OAuthClient.RedirectURL, OAuthClientForRequest(request).RedirectURL)
	}

	cfg.GenOAuth.RedirectURLs = nil
	request.Host = "vouch.example.com"
	assert.Equal(t, cfg.OAuthClient.RedirectURL, OAuthClientForRequest(request).RedirectURL)
}

func TestPrepareTokensAndClientUsesRequestCallbackURL(t *testing.T) {
	setUpOAuthClientForRequestTest(t)

	var redirectURIs []string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		redirectURIs = append(redirectURIs, r.Form.Get("redirect_uri"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"token","token_type":"Bearer"}`)
	}))
	defer tokenServer.Close()

	cfg.OAuthClient.Endpoint.TokenURL = tokenServer.URL
	cfg.OAuthClient.ClientID = "client-id"
	cfg.OAuthClient.ClientSecret = "client-secret"

	for _, host := range []string{"vouch.example.com", "vouch.other.com"} {
		request := httptest.NewRequest(http.MethodGet, "/auth/state/?code=code", nil)
		request.Host = host
		_, _, err := PrepareTokensAndClient(request, &structs.PTokens{}, false)
		assert.NoError(t, err)
	}

	assert.Equal(t, []string{
		"https://vouch.example.com/auth",
		"https://vouch.other.com/auth",
	}, redirectURIs)
}

func TestOAuthClientForRequestPreservesSingleCallbackConfiguration(t *testing.T) {
	setUpOAuthClientForRequestTest(t)

	singleCallbackURL := "https://vouch.single.example.com/auth"
	cfg.OAuthClient.RedirectURL = singleCallbackURL
	cfg.GenOAuth.RedirectURLs = nil

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.Host = "vouch.example.com"
	oauthClient := OAuthClientForRequest(request)

	assert.Equal(t, singleCallbackURL, oauthClient.RedirectURL)
	assert.Equal(t, singleCallbackURL, cfg.OAuthClient.RedirectURL)
	assert.NotSame(t, cfg.OAuthClient, oauthClient)
}
