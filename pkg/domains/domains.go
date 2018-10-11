package domains

import (
	"sort"
	"strings"

	"github.com/LassoProject/lasso/pkg/cfg"
	log "github.com/Sirupsen/logrus"
)

var domains = cfg.Cfg.Domains

func init() {
	sort.Sort(ByLengthDesc(domains))
}

// Matches returns one of the domains we're configured for
// TODO return all matches
// Matches return the first match of the
func Matches(s string) string {
	for i, v := range domains {
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

// ByLengthDesc sort from
// https://play.golang.org/p/N6GbEgBffd
type ByLengthDesc []string

func (s ByLengthDesc) Len() int {
	return len(s)
}
func (s ByLengthDesc) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// this differs by offing the longest first
func (s ByLengthDesc) Less(i, j int) bool {
	return len(s[j]) < len(s[i])
}
