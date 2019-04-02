package cfg

import (
	"testing"
	// "github.com/vouch/vouch-proxy/pkg/structs"
	"github.com/stretchr/testify/assert"
)

var (
	cfg config
)

func init() {
	// log.SetLevel(log.DebugLevel)
}

func TestConfigParsing(t *testing.T) {

	UnmarshalKey(Branding.LCName, &cfg)
	log.Debugf("cfgPort %d", cfg.Port)
	log.Debugf("cfgDomains %s", cfg.Domains[0])

	assert.Equal(t, cfg.Port, 9090)
	assert.Equal(t, cfg.Cookie.Name, "bnfSSO")

	assert.NotEmpty(t, cfg.JWT.MaxAge)

}
