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
