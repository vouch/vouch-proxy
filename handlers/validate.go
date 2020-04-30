package handlers

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"go.uber.org/zap"
)

// ValidateRequestHandler /validate
// TODO this should use the handler interface
func ValidateRequestHandler(w http.ResponseWriter, r *http.Request) {
	fastlog.Debug("/validate")

	// TODO: collapse all of the `if !cfg.Cfg.PublicAccess` calls
	// perhaps using an `ok=false` pattern
	jwt := findJWT(r)

	if jwt == "" {
		// If the module is configured to allow public access with no authentication, return 200 now
		if cfg.Cfg.PublicAccess {
			w.Header().Add(cfg.Cfg.Headers.User, "")
			log.Debugf("no jwt found, but public access is '%v', returning ok200", cfg.Cfg.PublicAccess)
			ok200(w, r)
		} else {
			error401(w, r, authError{Error: "no jwt found in request"})
		}
		return
	}

	// check to see if we have headers cached for this jwt
	if resp, found := jwtmanager.Cache.Get(jwt); found {
		// found it in cache!
		// fastlog.Debug("/validate found jwt response in cache")
		fastlog.Info("/validate found jwt response in cache")
		for k, v := range resp.(http.Header) {
			w.Header().Add(k, strings.Join(v, ","))
		}

		if cfg.Cfg.Testing {
			renderIndex(w, "user authorized "+w.Header().Get("X-Vouch-User"))
		} else {
			ok200(w, r)
		}
		return
	}

	claims, err := claimsFromJWT(jwt)
	if err != nil {
		// no email in jwt
		if !cfg.Cfg.PublicAccess {
			error401(w, r, authError{err.Error(), jwt})
		} else {
			w.Header().Add(cfg.Cfg.Headers.User, "")
		}
		return
	}

	if claims.Username == "" {
		// no email in jwt
		if !cfg.Cfg.PublicAccess {
			error401(w, r, authError{"no Username found in jwt", jwt})
		} else {
			w.Header().Add(cfg.Cfg.Headers.User, "")
		}
		return
	}
	fastlog.Info("jwt cookie",
		zap.String("username", claims.Username))

	if !cfg.Cfg.AllowAllUsers {
		if !jwtmanager.SiteInClaims(r.Host, &claims) {
			if !cfg.Cfg.PublicAccess {
				error401(w, r, authError{
					fmt.Sprintf("http header 'Host: %s' not authorized for configured `vouch.domains` (is Host being sent properly?)", r.Host),
					jwt})
			} else {
				w.Header().Add(cfg.Cfg.Headers.User, "")
			}
			return
		}
	}

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

	w.Header().Add(cfg.Cfg.Headers.User, claims.Username)
	w.Header().Add(cfg.Cfg.Headers.Success, "true")

	if cfg.Cfg.Headers.AccessToken != "" {
		if claims.PAccessToken != "" {
			w.Header().Add(cfg.Cfg.Headers.AccessToken, claims.PAccessToken)
		}
	}
	if cfg.Cfg.Headers.IDToken != "" {
		if claims.PIdToken != "" {
			w.Header().Add(cfg.Cfg.Headers.IDToken, claims.PIdToken)

		}
	}
	// fastlog.Debugf("response headers %+v", w.Header())
	// fastlog.Debug("response header",
	// 	zap.String(cfg.Cfg.Headers.User, w.Header().Get(cfg.Cfg.Headers.User)))
	fastlog.Debug("response header",
		zap.Any("all headers", w.Header()))

	// cache the headers against this jwt
	jwtmanager.Cache.SetDefault(jwt, w.Header().Clone())

	// ship it!
	if cfg.Cfg.Testing {
		renderIndex(w, "user authorized "+claims.Username)
	} else {
		ok200(w, r)
	}

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
