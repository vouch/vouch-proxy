/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package domains

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/vouch/vouch-proxy/pkg/cfg"
)

func init() {
	domains := []cfg.DomainOptions{
		{Uri: "vouch.github.io", ServiceId: "test_service"},
		{Uri: "sub.test.mydomain.com", ServiceId: "test_service"},
		{Uri: "test.mydomain.com", ServiceId: "test_service"},
	}
	cfg.InitForTestPurposes(&domains)
	Configure()
}

func TestIsUnderManagement(t *testing.T) {
	assert.True(t, IsUnderManagement("test@vouch.github.io"))
	assert.True(t, IsUnderManagement("test@sub.vouch.github.io"))
	assert.True(t, IsUnderManagement("test@test.mydomain.com"))
	assert.True(t, IsUnderManagement("test@sub.test.mydomain.com"))

	assert.False(t, IsUnderManagement("test@example.com"))
	assert.False(t, IsUnderManagement("vouch.github.io@example.com"))
	assert.False(t, IsUnderManagement("test-vouch.github.io@example.com"))
	assert.False(t, IsUnderManagement("test@vouch.github.io.com"))
}

func TestMatches(t *testing.T) {
	// Full email should not be accepted
	assert.Equal(t, "", cfg.Matches("test@vouch.github.io"))

	assert.Equal(t, "vouch.github.io", cfg.Matches("vouch.github.io"))
	assert.Equal(t, "vouch.github.io", cfg.Matches("sub.vouch.github.io"))
	assert.Equal(t, "", cfg.Matches("a-different-vouch.github.io"))

	assert.Equal(t, "", cfg.Matches("mydomain.com"))

	assert.Equal(t, "test.mydomain.com", cfg.Matches("test.mydomain.com"))
	assert.Equal(t, "sub.test.mydomain.com", cfg.Matches("sub.test.mydomain.com"))
	assert.Equal(t, "sub.test.mydomain.com", cfg.Matches("subsub.sub.test.mydomain.com"))
	assert.Equal(t, "test.mydomain.com", cfg.Matches("other.test.mydomain.com"))
}
