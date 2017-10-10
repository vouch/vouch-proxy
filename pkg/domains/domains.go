package domains

import (
	"strings"

	"github.com/bnfinet/lasso/pkg/cfg"
	log "github.com/Sirupsen/logrus"
)

// TODO sort domains by length from longest to shortest
// https://play.golang.org/p/N6GbEgBffd

// Matches returns one of the domains we're configured for
// TODO return all matches
func Matches(s string) string {
	for i, v := range cfg.Cfg.Domains {
		log.Debugf("domain matched array value at [%d]=%v", i, v)
		if strings.Contains(s, v) {
			return v
		}
	}
	return ""
}

// IsUnderManagement check if string contains a lasso managed domain
func IsUnderManagement(s string) bool {
	match := Matches(s)
	if match != "" {
		return true
	}
	return false
}
