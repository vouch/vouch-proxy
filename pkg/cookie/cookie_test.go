/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cookie

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/vouch/vouch-proxy/pkg/cfg"
)

func init() {
	cfg.InitForTestPurposes()
	Configure()
}

func TestSplitCookie(t *testing.T) {
	type args struct {
		longString string
		maxLen     int
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"small split", args{"AAAbbbCCCdddEEEfffGGGhhhIIIjjj", 3}, []string{"AAA", "bbb", "CCC", "ddd", "EEE", "fff", "GGG", "hhh", "III", "jjj"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitCookie(tt.args.longString, tt.args.maxLen); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCookie(t *testing.T) {
	cfg.Cfg.Cookie.Name = "_alpha_beta"
	ckValue1 := "charlie"
	ckValue2 := "delta"
	expectedValue := fmt.Sprintf("%s%s", ckValue1, ckValue2)

	r1 := &http.Request{
		Header: map[string][]string{
			"Cookie": {
				fmt.Sprintf("%s_1of2=%s", cfg.Cfg.Cookie.Name, ckValue1),
				fmt.Sprintf("%s_2of2=%s", cfg.Cfg.Cookie.Name, ckValue2),
			},
		},
	}

	r2TooBigCookieHeader := map[string][]string{}
	parts := maxCookieParts + 1
	for i := 1; i < parts; i++ {
		r2TooBigCookieHeader["Cookie"] = append(r2TooBigCookieHeader["Cookie"], fmt.Sprintf("%s_%dof%d=%d", cfg.Cfg.Cookie.Name, i, parts, i))
	}
	r2 := &http.Request{
		Header: r2TooBigCookieHeader,
	}

	r3 := &http.Request{
		Header: map[string][]string{"Cookie": {fmt.Sprintf("%s_1of100000000000=%s", cfg.Cfg.Cookie.Name, ckValue1)}},
	}

	r4 := &http.Request{
		Header: map[string][]string{"Cookie": {fmt.Sprintf("%s_100000000000000of32=%s", cfg.Cfg.Cookie.Name, ckValue1)}},
	}

	tests := []struct {
		name    string // description of this test case
		r       *http.Request
		want    string
		wantErr bool
	}{
		{"_alpha_beta", r1, expectedValue, false},
		{"too many parts", r2, "very big", true},
		{"just one but it claims to be big", r3, "very very big", true},
		{"just one but it has a big X in XofY", r4, "very very big", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// prepare the test by rendering the cookies into the response object
			tt.r.Cookies()

			got, gotErr := Cookie(tt.r)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Cookie() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Cookie() succeeded unexpectedly")
			}
			// should match
			if got != tt.want {
				t.Errorf("Cookie() = %v, want %v", got, tt.want)
			}
		})
	}
}
