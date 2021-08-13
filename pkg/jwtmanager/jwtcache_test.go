/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package jwtmanager

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func Test_getCacheExpirationDuration(t *testing.T) {
	// default cache expire is 20 minutes, so we test +/- 5 minutes of that
	expire = 17
	now := time.Now()

	claimsA := lc
	claimsA.ExpiresAt = now.Add(time.Minute * time.Duration(expire+5)).Unix()

	claimsB := lc
	dBexp := time.Minute * time.Duration(expire-5)
	claimsB.ExpiresAt = now.Add(dBexp).Unix()

	tests := []struct {
		name   string
		claims *VouchClaims
		want   time.Duration
	}{
		{fmt.Sprintf("should equal %d", expire), &claimsA, dExp}, // dExp is the default expiration duration
		{fmt.Sprintf("should equal %d -5", expire), &claimsB, dBexp},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getCacheExpirationDuration(tt.claims); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCacheExpirationDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
