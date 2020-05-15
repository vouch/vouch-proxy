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
	"testing"

	"github.com/vouch/vouch-proxy/pkg/cfg"
)

func TestLogoutHandler(t *testing.T) {
	setUp("/config/testing/handler_logout_url.yml")
	handler := http.HandlerFunc(LogoutHandler)

	tests := []struct {
		name     string
		url      string
		wantcode int
	}{
		{"allowed", "http://myapp.example.com/login", http.StatusFound},
		{"allowed", "https://oauth2.googleapis.com/revoke", http.StatusFound},
		{"not allowed", "http://myapp.example.com/loginagain", http.StatusBadRequest},
		{"not allowed", "http://google.com/", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/logout?url="+tt.url, nil)
			req.Host = "myapp.example.com"
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.wantcode {
				t.Errorf("LogoutHandler() status = %v, want %v", rr.Code, tt.wantcode)
			}
			if rr.Code == http.StatusFound && rr.Header().Get("Location") != tt.url {
				t.Errorf("LogoutHandler() redirect = %s, want %s", rr.Header().Get("Location"), tt.url)
			}
		})
	}
}

func TestProviderLogoutHandler(t *testing.T) {
	setUp("/config/testing/handler_logout_provider.yml")
	handler := http.HandlerFunc(LogoutHandler)

	tests := []struct {
		name     string
		url      string
		wantcode int
	}{
		{"allowed", "http://myapp.example.com/login", http.StatusFound},
		{"allowed", "https://oauth2.googleapis.com/revoke", http.StatusFound},
		{"not allowed", "http://myapp.example.com/loginagain", http.StatusBadRequest},
		{"not allowed", "http://google.com/", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/logout?url="+tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.wantcode {
				t.Errorf("LogoutHandler() status = %v, want %v", rr.Code, tt.wantcode)
			}
			if rr.Code == http.StatusFound {
				wanted := tt.url
				req, _ := http.NewRequest("GET", cfg.GenOAuth.LogoutURL, nil)

				q := req.URL.Query()
				q.Add("post_logout_redirect_uri", wanted)
				req.URL.RawQuery = q.Encode()
				wanted = req.URL.String()

				if rr.Header().Get("Location") != wanted {
					t.Errorf("LogoutHandler() redirect = %s, want %s", rr.Header().Get("Location"), wanted)
				}
			}
		})
	}
}
