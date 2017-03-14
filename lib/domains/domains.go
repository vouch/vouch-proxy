package domains

import (
	"strings"

	"git.fs.bnf.net/bnfinet/lasso/lib/cfg"
	log "github.com/Sirupsen/logrus"
)

// TODO sort domains by length from longest to shortest
// https://play.golang.org/p/N6GbEgBffd

// MatchingDomain returns one of the domains we're configured for
func MatchingDomain(s string) string {
	for i, v := range cfg.Cfg.Domains {
		log.Debugf("array value at [%d]=%v", i, v)
		if strings.Contains(s, v) {
			return v
		}
	}
	return ""
}

// DomainUnderManagement check if string contains a lasso managed domain
func DomainUnderManagement(s string) bool {
	match := MatchingDomain(s)
	if match != "" {
		return true
	}
	return false
}
