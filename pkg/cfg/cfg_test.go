package cfg

import (
	"testing"
	// "github.com/LassoProject/lasso/pkg/structs"
	// log "github.com/Sirupsen/logrus"
	log "github.com/Sirupsen/logrus"
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
