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
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.wantcode {
				t.Errorf("LogoutHandler() = %v, want %v", rr.Code, tt.wantcode)
			}
		})
	}
}
