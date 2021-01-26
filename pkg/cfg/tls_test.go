/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLSConfig(t *testing.T) {
	tests := []struct {
		name              string
		profile           string
		wantTLSMinVersion uint16
	}{
		{"TLSDefaultProfile", "", 0},
		{"TLSModernProfile", "modern", tls.VersionTLS13},
		{"TLSIntermediateProfile", "intermediate", tls.VersionTLS12},
		{"TLSOldProfile", "old", tls.VersionTLS10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig := TLSConfig(tt.profile)
			assert.Equal(t, tt.wantTLSMinVersion, tlsConfig.MinVersion)
		})
	}
}
