/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that 
can be found in the LICENSE file. Software distributed under The 
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"go.uber.org/zap"
)

var (
	errNoJWT  = errors.New("no jwt found in request")
	errNoUser = errors.New("no User found in jwt")
)

// ValidateRequestHandler /validate
// TODO this should use the handler interface
func ValidateRequestHandler(w http.ResponseWriter, r *http.Request) {
	fastlog.Debug("/validate")

	jwt := findJWT(r)
	if jwt == "" {
		send401or200PublicAccess(w, r, errNoJWT)
		return
	}

	claims, err := claimsFromJWT(jwt)
	if err != nil {
		send401or200PublicAccess(w, r, err)
		return
	}

	if claims.Username == "" {
		send401or200PublicAccess(w, r, errNoUser)
		return
	}

	if !cfg.Cfg.AllowAllUsers {
		if !jwtmanager.SiteInClaims(r.Host, &claims) {
			send401or200PublicAccess(w, r,
				fmt.Errorf("http header 'Host: %s' not authorized for configured `vouch.domains` (is Host being sent properly?)", r.Host))
			return
		}
	}

	generateCustomClaimsHeaders(w, claims)
	w.Header().Add(cfg.Cfg.Headers.User, claims.Username)

	w.Header().Add(cfg.Cfg.Headers.Success, "true")

	if cfg.Cfg.Headers.AccessToken != "" && claims.PAccessToken != "" {
		w.Header().Add(cfg.Cfg.Headers.AccessToken, claims.PAccessToken)
	}
	if cfg.Cfg.Headers.IDToken != "" && claims.PIdToken != "" {
		w.Header().Add(cfg.Cfg.Headers.IDToken, claims.PIdToken)
	}
	// fastlog.Debugf("response headers %+v", w.Header())
	// fastlog.Debug("response header",
	// 	zap.String(cfg.Cfg.Headers.User, w.Header().Get(cfg.Cfg.Headers.User)))
	fastlog.Debug("response header",
		zap.Any("all headers", w.Header()))

	// good to go!!
	if cfg.Cfg.Testing {
		renderIndex(w, "user authorized "+claims.Username)
	} else {
		ok200(w, r)
	}

	// TODO
	// parse the jwt and see if the claim is valid for the domain

}

func generateCustomClaimsHeaders(w http.ResponseWriter, claims jwtmanager.VouchClaims) {
	if len(cfg.Cfg.Headers.ClaimsCleaned) > 0 {
		log.Debug("Found claims in config, finding specific keys...")
		// Run through all the claims found
		for k, v := range claims.CustomClaims {
			// Run through the claims we are looking for
			for claim, header := range cfg.Cfg.Headers.ClaimsCleaned {
				// Check for matching claim
				if claim == k {
					log.Debugf("Found matching claim key: %s", k)
					if val, ok := v.([]interface{}); ok {
						strs := make([]string, len(val))
						for i, v := range val {
							strs[i] = fmt.Sprintf("\"%s\"", v)
						}
						log.Debugf("Adding header for claim %s - %s: %s", k, header, val)
						w.Header().Add(header, strings.Join(strs, ","))
					} else {
						// convert to string
						val := fmt.Sprint(v)
						if reflect.TypeOf(val).Kind() == reflect.String {
							// if val, ok := v.(string); ok {
							w.Header().Add(header, val)
							log.Debugf("Adding header for claim %s - %s: %s", k, header, val)
						} else {
							log.Errorf("Couldn't parse header type for %s %+v.  Please submit an issue.", k, v)
						}
					}
				}
			}
		}
	}

}

func send401or200PublicAccess(w http.ResponseWriter, r *http.Request, e error) {
	if cfg.Cfg.PublicAccess {
		log.Debugf("error: %s, but public access is '%v', returning ok200", e, cfg.Cfg.PublicAccess)
		w.Header().Add(cfg.Cfg.Headers.User, "")
		ok200(w, r)
		return
	}
	error401(w, r, e)
}

// findJWT look for JWT in Cookie, JWT Header, Authorization Header (OAuth2 Bearer Token)
// and Query String in that order
func findJWT(r *http.Request) string {
	jwt, err := cookie.Cookie(r)
	if err == nil {
		log.Debugf("jwt from cookie: %s", jwt)
		return jwt
	}
	jwt = r.Header.Get(cfg.Cfg.Headers.JWT)
	if jwt != "" {
		log.Debugf("jwt from header %s: %s", cfg.Cfg.Headers.JWT, jwt)
		return jwt
	}
	auth := r.Header.Get("Authorization")
	if auth != "" {
		s := strings.SplitN(auth, " ", 2)
		if len(s) == 2 {
			jwt = s[1]
			log.Debugf("jwt from authorization header: %s", jwt)
			return jwt
		}
	}
	jwt = r.URL.Query().Get(cfg.Cfg.Headers.QueryString)
	if jwt != "" {
		log.Debugf("jwt from querystring %s: %s", cfg.Cfg.Headers.QueryString, jwt)
		return jwt
	}
	return ""
}

// claimsFromJWT parse the jwt and return the claims
func claimsFromJWT(jwt string) (jwtmanager.VouchClaims, error) {
	var claims jwtmanager.VouchClaims

	jwtParsed, err := jwtmanager.ParseTokenString(jwt)
	if err != nil {
		// it didn't parse, which means its bad, start over
		log.Error("jwtParsed returned error, clearing cookie")
		return claims, err
	}

	claims, err = jwtmanager.PTokenClaims(jwtParsed)
	if err != nil {
		// claims = jwtmanager.PTokenClaims(jwtParsed)
		// if claims == &jwtmanager.VouchClaims{} {
		return claims, err
	}
	log.Debugf("JWT Claims: %+v", claims)
	return claims, nil
}
