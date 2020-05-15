/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package jwtmanager

import (
	"context"
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
func JWTCacheHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// return http.HandlerFunc(func(w CaptureWriter, r *http.Request) {

		// wrap ResponseWriter
		// v := CachedResponse{CaptureWriter: &CaptureWriter{ResponseWriter: w}}

		jwt := FindJWT(r)
		// check to see if we have headers cached for this jwt
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

		ctx := context.Background()
		next.ServeHTTP(w, r.WithContext(ctx))

		// cache the response against this jwt
		go func() {
			// Cache.SetDefault(jwt, v.RawDump())
			Cache.SetDefault(jwt, w.Header().Clone())
		}()

	})
}

// func (cr *CachedResponse) Write(b []byte) (int, error) {
// 	cr.rawResponse = append(cr.rawResponse, b[:]...)
// 	return cr.CaptureWriter.Write(b)
// }

// // Header calls http.Writer.Header()
// func (cr *CachedResponse) Header() http.Header {
// 	return cr.CaptureWriter.Header()
// }

// // WriteHeader calls http.Writer.WriteHeader(code)
// func (cr *CachedResponse) WriteHeader(code int) {
// 	cr.CaptureWriter.WriteHeader(code)
// }

// // RawDump constructs the contents to be cached
// func (cr *CachedResponse) RawDump() []byte {
// 	var dump bytes.Buffer
// 	for k, v := range cr.Header().Clone() {
// 		dump.WriteString(fmt.Sprintf("%s: %s", k, strings.Join(v, ",")))
// 		dump.WriteRune('\n')
// 	}
// 	dump.WriteRune('\n')
// 	dump.Write(cr.rawResponse)
// 	return dump.Bytes()
// }
