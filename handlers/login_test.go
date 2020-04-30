package handlers

import "testing"

func Test_validateRequestedURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"no https", "example.com/dest", true},
		{"redirection chaining", "http://example.com/dest?url=https://", true},
		{"data uri", "http://example.com/dest?url=data:text/plain,Example+Text", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequestedURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("cleanRequestedURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if got != tt.want {
			// 	t.Errorf("cleanRequestedURL() = %v, want %v", got, tt.want)
			// }
		})
	}
}
