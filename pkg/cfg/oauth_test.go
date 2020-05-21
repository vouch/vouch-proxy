/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"testing"
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
