/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package jwtmanager

import (
	"net/http"
	"strings"
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/responses"
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
	Cache = cache.New(dExp, purgeCheck)
	log.Infof("jwtcache: the returned headers for a valid jwt will be cached for %d minutes", expire)
}

// CachedResponse caches the JWT response
// type CachedResponse struct {
// 	*CaptureWriter
// 	rawResponse []byte
// }

// JWTCacheHandler looks for a JWT and...
// returns a cached response
// or passes the JWT in the context
// tests for JWTCacheHandler are present in `handlers/validate_test.go` to avoid circular imports
func JWTCacheHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// return http.HandlerFunc(func(w CaptureWriter, r *http.Request) {

		// wrap ResponseWriter
		// v := CachedResponse{CaptureWriter: &CaptureWriter{ResponseWriter: w}}

		jwt := FindJWT(r)
		// check to see if we have headers cached for this jwt
		if jwt != "" {
			if resp, found := Cache.Get(jwt); found {
				// found it in cache!
				logger.Debug("/validate found response headers for jwt in cache")
				// TODO: instead of the copy for each, can we just append the whole blob?
				// or better still can we just cache the entire response including 200OK?
				for k, v := range resp.(http.Header) {
					w.Header().Add(k, strings.Join(v, ","))

				}

				responses.OK200(w, r)

				return
			}
		}

		next.ServeHTTP(w, r)

		if jwt != "" &&
			r.Context().Err() == nil { // r.Context().Done() is still open
			// cache the response headers for this jwt
			// log.Debug("setting cache for %+v", w.Header().Clone())
			Cache.SetDefault(jwt, w.Header().Clone())
		}
	})
}
