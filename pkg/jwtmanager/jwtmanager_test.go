/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package jwtmanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

var (
	u1 = structs.User{
		Username: "test@testing.com",
		Name:     "Test Name",
	}
	t1 = structs.PTokens{
		PAccessToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRvaXU4In0.eyJzdWIiOiJuZnlmZSIsImF1ZCI6ImltX29pY19jbGllbnQiLCJqdGkiOiJUOU4xUklkRkVzUE45enU3ZWw2eng2IiwiaXNzIjoiaHR0cHM6XC9cL3Nzby5tZXljbG91ZC5uZXQ6OTAzMSIsImlhdCI6MTM5MzczNzA3MSwiZXhwIjoxMzkzNzM3MzcxLCJub25jZSI6ImNiYTU2NjY2LTRiMTItNDU2YS04NDA3LTNkMzAyM2ZhMTAwMiIsImF0X2hhc2giOiJrdHFvZVBhc2praVY5b2Z0X3o5NnJBIn0.g1Jc9DohWFfFG3ppWfvW16ib6YBaONC5VMs8J61i5j5QLieY-mBEeVi1D3vr5IFWCfivY4hZcHtoJHgZk1qCumkAMDymsLGX-IGA7yFU8LOjUdR4IlCPlZxZ_vhqr_0gQ9pCFKDkiOv1LVv5x3YgAdhHhpZhxK6rWxojg2RddzvZ9Xi5u2V1UZ0jukwyG2d4PRzDn7WoRNDGwYOEt4qY7lv_NO2TY2eAklP-xYBWu0b9FBElapnstqbZgAXdndNs-Wqp4gyQG5D0owLzxPErR9MnpQfgNcai-PlWI_UrvoopKNbX0ai2zfkuQ-qh6Xn8zgkiaYDHzq4gzwRfwazaqA",
		PIdToken:     "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRvaXU4In0.eyJzdWIiOiJuZnlmZSIsImF1ZCI6ImltX29pY19jbGllbnQiLCJqdGkiOiJUOU4xUklkRkVzUE45enU3ZWw2eng2IiwiaXNzIjoiaHR0cHM6XC9cL3Nzby5tZXljbG91ZC5uZXQ6OTAzMSIsImlhdCI6MTM5MzczNzA3MSwiZXhwIjoxMzkzNzM3MzcxLCJub25jZSI6ImNiYTU2NjY2LTRiMTItNDU2YS04NDA3LTNkMzAyM2ZhMTAwMiIsImF0X2hhc2giOiJrdHFvZVBhc2praVY5b2Z0X3o5NnJBIn0.g1Jc9DohWFfFG3ppWfvW16ib6YBaONC5VMs8J61i5j5QLieY-mBEeVi1D3vr5IFWCfivY4hZcHtoJHgZk1qCumkAMDymsLGX-IGA7yFU8LOjUdR4IlCPlZxZ_vhqr_0gQ9pCFKDkiOv1LVv5x3YgAdhHhpZhxK6rWxojg2RddzvZ9Xi5u2V1UZ0jukwyG2d4PRzDn7WoRNDGwYOEt4qY7lv_NO2TY2eAklP-xYBWu0b9FBElapnstqbZgAXdndNs-Wqp4gyQG5D0owLzxPErR9MnpQfgNcai-PlWI_UrvoopKNbX0ai2zfkuQ-qh6Xn8zgkiaYDHzq4gzwRfwazaqA",
        PRefreshToken: "",
	}

	lc VouchClaims

	claimjson = `{
		"sub": "f:a95afe53-60ba-4ac6-af15-fab870e72f3d:mrtester",
		"groups": ["Website Users", "Test Group"],
		"given_name": "Mister",
		"family_name": "Tester",
		"email": "mrtester@test.int"
	}`
	customClaims = structs.CustomClaims{}
)

func init() {
	cfg.InitForTestPurposes()
	Configure()

	lc = VouchClaims{
		u1.Username,
		customClaims.Claims,
		t1.PAccessToken,
        t1.PRefreshToken,
		t1.PIdToken,
		RegisteredClaims,
	}
}

func setUp(t *testing.T, cfgFile string) {
	rootDir := os.Getenv(cfg.Branding.UCName + "_ROOT")
	if err := os.Setenv(cfg.Branding.UCName+"_CONFIG", filepath.Join(rootDir, "config/testing", cfgFile)); err != nil {
		t.Errorf("failed setting environment variable %s_CONFIG", cfg.Branding.UCName)
	}
	Configure()
	cfg.InitForTestPurposes()
}

func TestClaimsHMAC(t *testing.T) {
	for _, cfgFile := range []string{"test_config.yml", "test_config_rsa.yml"} {
		setUp(t, cfgFile)
		json.Unmarshal([]byte(claimjson), &customClaims.Claims)

		log.Debugf("jwt config %s %d", string(cfg.Cfg.JWT.Secret), cfg.Cfg.JWT.MaxAge)
		assert.NotEmpty(t, cfg.Cfg.JWT.SigningMethod)
		assert.NotEmpty(t, cfg.Cfg.JWT.MaxAge)

		uts, err := NewVPJWT(u1, customClaims, t1)
		assert.NoError(t, err)

		utsParsed, err := ParseTokenString(uts)
		assert.NoError(t, err)

		log.Infof("utsParsed: %+v", utsParsed)
		// log.Infof("Sites: %+v", Sites)
		assert.True(t, SiteInToken(cfg.Cfg.Domains[0], utsParsed))
	}
	json.Unmarshal([]byte(claimjson), &customClaims.Claims)
}

func TestClaims(t *testing.T) {
	setUp(t, "test_config.yml")
	aud = audience()
	log.Debugf("jwt config %s %d", string(cfg.Cfg.JWT.Secret), cfg.Cfg.JWT.MaxAge)
	assert.NotEmpty(t, cfg.Cfg.JWT.Secret)
	assert.NotEmpty(t, cfg.Cfg.JWT.MaxAge)

	// now := time.Now()
	// d := time.Duration(ExpiresAtMinutes) * time.Minute
	// log.Infof("lc d %s", d.String())
	// lc.StandardClaims.ExpiresAt = now.Add(time.Duration(ExpiresAtMinutes) * time.Minute).Unix()
	// log.Infof("lc expiresAt %d", now.Unix()-lc.StandardClaims.ExpiresAt)
	uts, err := NewVPJWT(u1, customClaims, t1)
	assert.NoError(t, err)
	utsParsed, _ := ParseTokenString(uts)
	log.Infof("utsParsed: %+v", utsParsed)
	log.Infof("Audience: %+v", aud)
	assert.True(t, SiteInToken(cfg.Cfg.Domains[0], utsParsed))
}

func TestVouchClaims_SiteInAudience(t *testing.T) {
	tests := []struct {
		name    string
		cfgFile string
		s       string
		want    bool
	}{
		{"exact match", "test_config_oauth_claims.yml", "vouch.github.io", true},
		{"subdomain match", "test_config_oauth_claims.yml", "sub.vouch.github.io", true},
		{"suffix attack", "test_config_oauth_claims.yml", "evilvouch.github.io", false},
		{"attacker parent domain", "test_config_oauth_claims.yml", "vouch.github.io.attacker.com", false},
		{"attacker combined", "test_config_oauth_claims.yml", "evilvouch.github.io.attacker.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUp(t, tt.cfgFile)
			jwt, err := NewVPJWT(u1, customClaims, t1)
			assert.NoError(t, err)
			claims, err := ClaimsFromJWT(jwt)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			got := claims.SiteInAudience(tt.s)
			if got != tt.want {
				t.Errorf("SiteInAudience(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestSiteInAudienceLegacyFormat(t *testing.T) {
	claims := &VouchClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"vouch.github.io,other.test"},
		},
	}

	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"exact first", "vouch.github.io", true},
		{"exact second", "other.test", true},
		{"subdomain first", "sub.vouch.github.io", true},
		{"subdomain second", "sub.other.test", true},
		{"suffix attack first", "evilvouch.github.io", false},
		{"suffix attack second", "evilother.test", false},
		{"attacker parent", "vouch.github.io.attacker.com", false},
		{"unrelated", "evil.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claims.SiteInAudience(tt.s)
			if got != tt.want {
				t.Errorf("SiteInAudience(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}
