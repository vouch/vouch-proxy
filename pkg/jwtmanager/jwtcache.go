/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package jwtmanager

import (
	"time"

	cache "github.com/patrickmn/go-cache"
	"github.com/vouch/vouch-proxy/pkg/cfg"
)

// Cache in memory temporary store for responses from /validate for jwt
var Cache *cache.Cache

func cacheConfigure() {

	var expire int = 20 // default 20 minutes

	if cfg.Cfg.JWT.MaxAge < expire {
		expire = cfg.Cfg.JWT.MaxAge
	}
	dExp := time.Duration(expire) * time.Minute
	purgeCheck := dExp / 5
	// log.Debugf("cacheConfigure expire %d dExp %d purgecheck %d", expire, dExp, purgeCheck)
	log.Infof("jwtmanager: the returned headers for a valid jwt will be cached for %d minutes", expire)
	Cache = cache.New(dExp, purgeCheck)
}
