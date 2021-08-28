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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vouch/vouch-proxy/pkg/cfg"
)

func TestCallbackHandlerDocumentRoot(t *testing.T) {
	handlerL := http.HandlerFunc(LoginHandler)
	handlerA := http.HandlerFunc(CallbackHandler)

	tests := []struct {
		name       string
		configFile string
		wantcode   int
	}{
		{"should have URL that begins with DocumentRoot", "/config/testing/handler_login_url_document_root.yml", http.StatusFound},
		{"should have URL that does not begin with DocumentRoot", "/config/testing/handler_login_url.yml", http.StatusFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUp(tt.configFile)

			// first make a request of /login to set the session cookie
			reqLogin, err := http.NewRequest("GET", cfg.Cfg.DocumentRoot+"/login?url=http://myapp.example.com/logout", nil)
			reqLogin.Header.Set("Host", "my.example.com")
			if err != nil {
				t.Fatal(err)
			}
			rrL := httptest.NewRecorder()
			handlerL.ServeHTTP(rrL, reqLogin)

			// grab the state from the session cookie to
			session, err := sessstore.Get(reqLogin, cfg.Cfg.Session.Name)
			state := session.Values["state"].(string)

			// now mimic an IdP returning the state variable back to us
			reqAuth, err := http.NewRequest("GET", cfg.Cfg.DocumentRoot+"/auth?state="+state, nil)
			reqAuth.Header.Set("Host", "my.example.com")
			if err != nil {
				t.Fatal(err)
			}
			// transfer the cookie from rrL to reqAuth
			rrA := httptest.NewRecorder()

			handlerA.ServeHTTP(rrA, reqAuth)
			if rrA.Code != tt.wantcode {
				t.Errorf("LoginHandler() status = %v, want %v", rrA.Code, tt.wantcode)
			}

			// confirm the requst to $DocumentRoot/auth is redirected to $DocumentRoot/auth/$state
			redirectURL, err := url.Parse(rrA.Header()["Location"][0])
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, fmt.Sprintf("%s/auth/%s/", cfg.Cfg.DocumentRoot, state), redirectURL.Path)

		})
	}
}

func TestAuthStateHandler(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AuthStateHandler(tt.args.w, tt.args.r)
		})
	}
}
