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
				t.Errorf("LogoutHandler() status = %v, want %v", rr.Code, tt.wantcode)
			}
			if (rr.Code == http.StatusFound && rr.Header().Get("Location") != tt.url) {
				t.Errorf("LogoutHandler() redirect = %s, want %s", rr.Header().Get("Location"), tt.url)
			}
		})
	}
}
