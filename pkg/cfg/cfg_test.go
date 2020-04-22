package cfg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigParsing(t *testing.T) {
	InitForTestPurposes()
	Configure()

	// UnmarshalKey(Branding.LCName, &cfg)
	log.Debugf("cfgPort %d", Cfg.Port)
	log.Debugf("cfgDomains %s", Cfg.Domains[0])

	assert.Equal(t, Cfg.Port, 9090)

	assert.NotEmpty(t, Cfg.JWT.MaxAge)

}

func TestSetGitHubDefaults(t *testing.T) {
	InitForTestPurposesWithProvider("github")
	assert.Equal(t, []string{"read:user"}, GenOAuth.Scopes)
}

func TestSetGitHubDefaultsWithTeamWhitelist(t *testing.T) {
	InitForTestPurposesWithProvider("github")
	Cfg.TeamWhiteList = append(Cfg.TeamWhiteList, "org/team")
	GenOAuth.Scopes = []string{}

	setDefaultsGitHub()
	assert.Contains(t, GenOAuth.Scopes, "read:user")
	assert.Contains(t, GenOAuth.Scopes, "read:org")
}

func Test_claimToHeader(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    string
		wantErr bool
	}{
		{"remove http://", "http://test.example.com", Cfg.Headers.ClaimHeader + "Test.example.com", false},
		{"remove https://", "https://test.example.com", Cfg.Headers.ClaimHeader + "Test.example.com", false},
		{"auth0 fix https://", "https://test.auth0.com/user", Cfg.Headers.ClaimHeader + "Test.auth0.com-User", false},
		{"cognito user:groups", "user:groups", Cfg.Headers.ClaimHeader + "User-Groups", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := claimToHeader(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("claimToHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("claimToHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}
