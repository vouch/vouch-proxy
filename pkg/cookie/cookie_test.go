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
	r := &http.Request{
		Header: map[string][]string{
			"Cookie": {
				fmt.Sprintf("%s_1of2=%s", cfg.Cfg.Cookie.Name, ckValue1),
				fmt.Sprintf("%s_2of2=%s", cfg.Cfg.Cookie.Name, ckValue2),
			},
		},
	}
	r.Cookies()
	s, err := Cookie(r)
	if err != nil {
		t.Error(err)
	}
	if expectedValue != s {
		t.Errorf("expected \"%s\" received \"%s\"", expectedValue, s)
	}
}
