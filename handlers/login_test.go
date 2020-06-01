/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vouch/vouch-proxy/pkg/cfg"
)

func Test_getValidRequestedURL(t *testing.T) {
	setUp("/config/testing/handler_login_url.yml")
	r := &http.Request{}
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{"no https", "example.com/dest", "", true},
		{"redirection chaining", "http://example.com/dest?url=https://", "", true},
		{"redirection chaining upper case", "http://example.com/dest?url=HTTPS://someplaceelse.com", "", true},
		{"redirection chaining no protocol", "http://example.com/dest?url=//someplaceelse.com", "", true},
		{"data uri", "http://example.com/dest?url=data:text/plain,Example+Text", "", true},
		{"javascript uri", "http://example.com/dest?url=javascript:alert(1)", "", true},
		{"not in domain", "http://somewherelse.com/", "", true},
		{"should warn", "https://example.com/", "https://example.com/", false},
		{"should be fine", "http://example.com/", "http://example.com/", false},
		{"multiple query param", "http://example.com/?strange=but-true&also-strange=but-false", "http://example.com/?strange=but-true&also-strange=but-false", false},
		{"multiple query params, one of them bad", "http://example.com/?strange=but-true&also-strange=but-false&strange-but-bad=https://badandstrange.com", "", true},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r.URL, _ = url.Parse("http://vouch.example.com/login?url=" + tt.url)
			got, err := getValidRequestedURL(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("getValidRequestedURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getValidRequestedURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoginHandler(t *testing.T) {
	handler := http.HandlerFunc(LoginHandler)

	tests := []struct {
		name       string
		configFile string
		wantcode   int
	}{
		{"general test", "/config/testing/handler_login_url.yml", http.StatusFound},
		{"general test", "/config/testing/handler_login_redirecturls.yml", http.StatusFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUp(tt.configFile)

			req, err := http.NewRequest("GET", "/logout?url=http://myapp.example.com/login", nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantcode {
				t.Errorf("LogoutHandler() status = %v, want %v", rr.Code, tt.wantcode)
			}

			// confirm the OAuthClient has a properly configured
			redirectURL, err := url.Parse(rr.Header()["Location"][0])
			if err != nil {
				t.Fatal(err)
			}
			redirectParam := redirectURL.Query().Get("redirect_uri")
			assert.NotEmpty(t, cfg.OAuthClient.RedirectURL, "cfg.OAuthClient.RedirectURL is empty")
			assert.NotEmpty(t, redirectParam, "redirect_uri should not be empty when redirected to google oauth")

		})
	}
}
