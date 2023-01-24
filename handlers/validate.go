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

	"go.uber.org/zap"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/responses"
)

var (
	errNoJWT = errors.New("no jwt found in request")
	errNoSub = errors.New("no 'sub' found in jwt")
)

// ValidateRequestHandler /validate
func ValidateRequestHandler(w http.ResponseWriter, r *http.Request) {
	fastlog.Debug("/validate")

	jwt := jwtmanager.FindJWT(r)
	if jwt == "" {
		send401or200PublicAccess(w, r, errNoJWT)
		return
	}

	claims, err := jwtmanager.ClaimsFromJWT(jwt)
	if err != nil {
		send401or200PublicAccess(w, r, err)
		return
	}

	if claims.Sub == "" {
		send401or200PublicAccess(w, r, errNoSub)
		return
	}

	if !cfg.Cfg.AllowAllUsers {
		if !claims.SiteInAudience(r.Host) {
			send401or200PublicAccess(w, r,
				fmt.Errorf("http header 'Host: %s' not authorized for configured `vouch.domains` (is Host being sent properly?)", r.Host))
			return
		}
	}

	generateCustomClaimsHeaders(w, claims)
	w.Header().Add(cfg.Cfg.Headers.Sub, claims.Sub)
	if claims.Username != "" {
		w.Header().Add(cfg.Cfg.Headers.User, claims.Username)
	}
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
		responses.RenderIndex(w, "user authorized "+claims.Username)
	} else {
		responses.OK200(w, r)
	}

	// TODO
	// parse the jwt and see if the claim is valid for the domain

}

func generateCustomClaimsHeaders(w http.ResponseWriter, claims *jwtmanager.VouchClaims) {
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
		log.Debugf("error: %s, but public access is '%v', returning OK200", e, cfg.Cfg.PublicAccess)
		w.Header().Add(cfg.Cfg.Headers.User, "")
		responses.OK200(w, r)
		return
	}

	responses.Error401(w, r, e)
}
