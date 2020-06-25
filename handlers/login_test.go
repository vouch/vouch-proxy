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

func Test_normalizeLoginURL(t *testing.T) {
	setUp("/config/testing/handler_login_url.yml")
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		// This is not an RFC-compliant URL because it does not encode :// in the url param; we accept it anyway
		{"extra params", "http://host/login?url=http://host/path?p2=2", "http://host/path?p2=2", false},
		{"extra params (blank)", "http://host/login?url=http://host/path?p2=", "http://host/path?p2=", false},
		// This is not an RFC-compliant URL because it does not encode :// in the url param; we accept it anyway
		// Even though the p1 param is not a login param, we do not interpret is as part of the url param because it precedes it
		{"prior params", "http://host/login?p1=1&url=http://host/path", "http://host/path", true},
		// This is not an RFC-compliant URL because it does not encode :// in the url param; we accept it anyway
		// We assume vouch-* is a login param and do not fold it into url
		{"vouch-* params after", "http://host/login?url=http://host/path&vouch-xxx=2", "http://host/path", false},
		// This is not an RFC-compliant URL because it does not encode :// in the url param; we accept it anyway
		// We assume vouch-* is a login param and do not fold it into url
		{"vouch-* params before", "http://host/login?vouch-xxx=1&url=http://host/path", "http://host/path", false},
		// This is not an RFC-compliant URL because it does not encode :// in the url param; we accept it anyway
		// We assume x-vouch-* is a login param and do not fold it into url
		{"x-vouch-* params after", "http://host/login?url=http://host/path&vouch-xxx=2", "http://host/path", false},
		// This is not an RFC-compliant URL because it does not encode :// in the url param; we accept it anyway
		// We assume x-vouch-* is a login param and do not fold it into url
		{"x-vouch-* params before", "http://host/login?x-vouch-xxx=1&url=http://host/path", "http://host/path", false},
		// This is not an RFC-compliant URL because it does not encode :// in the url param; we accept it anyway
		// Even though p1 is not a login param, we do not interpret is as part of url because it follows a login param (vouch-*)
		{"params after vouch-* params", "http://host/login?url=http://host/path&vouch-xxx=2&p3=3", "http://host/path", true},
		// This is not an RFC-compliant URL because it does not encode :// in the url param; we accept it anyway
		// Even though p1 is not a login param, we do not interpret is as part of url because it follows a login param (x-vouch-*)
		{"params after x-vouch-* params", "http://host/login?url=http://host/path&x-vouch-xxx=2&p3=3", "http://host/path", true},
		// This is not an RFC-compliant URL; it combines all the aspects above
		{"all params", "http://host/login?p1=1&url=http://host/path?p2=2&p3=3&x-vouch-xxx=4&vouch=5&error=6&p7=7", "http://host/path?p2=2&p3=3", true},
		// This is an RFC-compliant URL
		{"all params (encoded)", "http://host/login?p1=1&url=http%3a%2f%2fhost/path%3fp2=2%26p3=3&x-vouch-xxx=4&vouch=5&error=6&p7=7", "http://host/path?p2=2&p3=3", true},
		// This is not an RFC-compliant URL; it combines all the aspects above, and it uses semicolons as parameter separators
		// Note that when we fold a stray param into the url param, we always do so with &s
		{"all params (semicolons)", "http://host/login?p1=1;url=http://host/path?p2=2;p3=3;x-vouch-xxx=4;p5=5", "http://host/path?p2=2&p3=3", true},
		// This is an RFC-compliant URL that uses semicolons as parameter separators
		{"all params (encoded, semicolons)", "http://host/login?p1=1;url=http%3a%2f%2fhost/path%3fp2=2%3bp3=3;x-vouch-xxx=4;p5=5", "http://host/path?p2=2;p3=3", true},
		// Real world tests
		// since v0.4.0 the vouch README has specified an Nginx config including a 302 redirect in the following format...
		{"Vouch README (with error)", "http://host/login?url=http://host/path?p2=2&vouch-failcount=3&X-Vouch-Token=TOKEN&error=anerror", "http://host/path?p2=2", false},
		{"Vouch README (blank error)", "http://host/login?url=http://host/path?p2=2&vouch-failcount=&X-Vouch-Token=&error=", "http://host/path?p2=2", false},
		{"Vouch README (semicolons, blank error)", "http://host/login?url=http://host/path?p2=2;p3=3&vouch-failcount=&X-Vouch-Token=&error=", "http://host/path?p2=2&p3=3", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.url)
			got, err := normalizeLoginURLParam(u)
			if got.String() != tt.want {
				t.Errorf("normalizeLoginURLParam() = %v, want %v", got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeLoginURLParam() err = %v", err)
			}
		})
	}
}

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
		{"redirection chaining escaped https://", "http://example.com/dest?url=https%3a%2f%2fsomeplaceelse.com", "", true},
		{"data uri", "http://example.com/dest?url=data:text/plain,Example+Text", "", true},
		{"javascript uri", "http://example.com/dest?url=javascript:alert(1)", "", true},
		{"not in domain", "http://somewherelse.com/", "", true},
		{"should warn", "https://example.com/", "https://example.com/", false},
		{"should be fine", "http://example.com/", "http://example.com/", false},
		{"multiple query param", "http://example.com/?strange=but-true&also-strange=but-false", "http://example.com/?strange=but-true&also-strange=but-false", false},
		{"multiple query params, one of them bad", "http://example.com/?strange=but-true&also-strange=but-false&strange-but-bad=https://badandstrange.com", "", true},
		{"multiple query params, one of them bad (escaped)", "http://example.com/?strange=but-true&also-strange=but-false&strange-but-bad=https%3a%2f%2fbadandstrange.com", "", true},
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
