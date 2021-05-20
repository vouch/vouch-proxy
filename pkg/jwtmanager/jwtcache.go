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
var expire int = 20 // default 20 minutes
var dExp time.Duration

func cacheConfigure() {

	if cfg.Cfg.JWT.MaxAge < expire {
		expire = cfg.Cfg.JWT.MaxAge
	}
	dExp = time.Duration(expire) * time.Minute
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
// or passes the request to /validate
// all tests for JWTCacheHandler are present in `handlers/validate_test.go` to avoid circular imports
func JWTCacheHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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
			r.Context().Err() == nil {
			// see responses.addErrandCancelRequest()
			// r.Context().Done() is still open
			// cache the response headers for this jwt
			// log.Debug("setting cache for %+v", w.Header().Clone())

			claims, err := ClaimsFromJWT(jwt)
			now := time.Now().Unix()
			if err != nil {
				log.Error("very unusual error, we found a jwt for /validate but we couldn't parse it for claims while setting it into cache, returning")
				return
				// log.Debugf("*HERE* claims expire, time.now.unix, dExp %d - %d = %d > %d", claims.ExpiresAt, now, claims.ExpiresAt-now, int64(dExp))
				// log.Debugf("*HERE* time.Duration((claims.ExpiresAt-time.Now().Unix())*time.Second.Nanoseconds()) %d", time.Duration((claims.ExpiresAt-time.Now().Unix())*time.Second.Nanoseconds()))
			}

			// first see if the jwt's expiration will arrive before the cache expiration
			// if this jwt expires in 10 minutes then we don't want to cache it for 20
			// this might happen if the jwt expiration is set to 240 minutes, and the user last logged into the IdP 230 minutes ago
			// then the user went away, cache was purged and now they return with 10 minutes left before token expiration
			if !claims.VerifyExpiresAt(now+int64(dExp/time.Second), true) {
				jwtExpiresIn := time.Duration((claims.ExpiresAt - now) * int64(time.Second))
				log.Debugf("cache default expiration (%d) is after claim expiration (%d). setting cache experation to claim expiration for this entry", dExp, jwtExpiresIn)
				Cache.Set(jwt, w.Header().Clone(), jwtExpiresIn)
			} else {
				Cache.SetDefault(jwt, w.Header().Clone())
			}

		}
	})
}
