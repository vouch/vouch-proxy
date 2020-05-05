package handlers

import (
	"net/http"
	"net/url"
	"testing"
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
