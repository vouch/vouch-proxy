/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package domains

import (
	"sort"
	"strings"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"go.uber.org/zap"
)

var log *zap.SugaredLogger

// Configure see main.go configure()
func Configure() {
	log = cfg.Logging.Logger
	sort.Sort(ByUri(cfg.Cfg.Domains))
}

// IsUnderManagement check if an email is under vouch-managed domain
func IsUnderManagement(email string) bool {
	split := strings.Split(email, "@")
	if len(split) != 2 {
		log.Warnf("not a valid email: %s", email)
		return false
	}

	match := cfg.Matches(split[1])
	if match != "" {
		return true
	}
	return false
}

// ByLengthDesc sort from
// https://play.golang.org/p/N6GbEgBffd
type ByUri cfg.DomainsOptions

func (s ByUri) Len() int {
	return len(s)
}
func (s ByUri) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// this differs by sorting by Uri
func (s ByUri) Less(i, j int) bool {
	return s[j].Uri < s[i].Uri
}
