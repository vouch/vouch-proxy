package domains

import (
	"sort"
	"strings"

	"github.com/vouch/vouch-proxy/pkg/cfg"
)

var domains = cfg.Cfg.Domains
var log = cfg.Cfg.Logger

func init() {
	sort.Sort(ByLengthDesc(domains))
}

func Refresh() {
	domains = cfg.Cfg.Domains
	sort.Sort(ByLengthDesc(domains))
}

// Matches returns one of the domains we're configured for
// TODO return all matches
// Matches return the first match of the
func Matches(s string) string {
	for i, v := range domains {
		if s == v || strings.HasSuffix(s, "." + v) {
			log.Debugf("domain %s matched array value at [%d]=%v", s, i, v)
			return v
		}
	}
	log.Warnf("domain %s not found in any domains %v", s, domains)
	return ""
}

// IsUnderManagement check if an email is under vouch-managed domain
func IsUnderManagement(email string) bool {
	split := strings.Split(email, "@")
	if len(split) != 2 {
		log.Warnf("not a valid email: %s", email)
		return false
	}

	match := Matches(split[1])
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
