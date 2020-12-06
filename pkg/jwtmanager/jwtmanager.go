/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package jwtmanager

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

// const numSites = 2

// VouchClaims jwt Claims specific to vouch
type VouchClaims struct {
	Sub          string   `json:"sub"`
	Username     string   `json:"username"`
	Sites        []string `json:"sites"` // tempting to make this a map but the array is fewer characters in the jwt
	CustomClaims map[string]interface{}
	PAccessToken string
	PIdToken     string
	jwt.StandardClaims
}

// StandardClaims jwt.StandardClaims implementation
var StandardClaims jwt.StandardClaims

// CustomClaims implementation
// var CustomClaims map[string]interface{}

// Sites added to VouchClaims
var Sites []string
var logger *zap.Logger
var log *zap.SugaredLogger

// Configure see main.go configure()
func Configure() {
	log = cfg.Logging.Logger
	logger = cfg.Logging.FastLogger
	cacheConfigure()
	StandardClaims = jwt.StandardClaims{
		Issuer: cfg.Cfg.JWT.Issuer,
	}
	populateSites()
}

func populateSites() {
	Sites = make([]string, 0)
	// TODO: the Sites that end up in the JWT come from here
	// if we add fine grain ability (ACL?) to the equation
	// then we're going to have to add something fancier here
	for i := 0; i < len(cfg.Cfg.Domains); i++ {
		Sites = append(Sites, cfg.Cfg.Domains[i])
	}
}

// CreateUserTokenString converts user to signed jwt
func CreateUserTokenString(u structs.User, customClaims structs.CustomClaims, ptokens structs.PTokens) string {
	// User`token`
	// u.PrepareUserData()
	claims := VouchClaims{
		u.Sub,
		u.Username,
		Sites,
		customClaims.Claims,
		ptokens.PAccessToken,
		ptokens.PIdToken,
		StandardClaims,
	}

	// https://github.com/vouch/vouch-proxy/issues/287
	if cfg.Cfg.Headers.AccessToken == "" {
		claims.PAccessToken = ""
	}

	if cfg.Cfg.Headers.IDToken == "" {
		claims.PIdToken = ""
	}

	claims.StandardClaims.ExpiresAt = time.Now().Add(time.Minute * time.Duration(cfg.Cfg.JWT.MaxAge)).Unix()

	// https://godoc.org/github.com/dgrijalva/jwt-go#NewWithClaims
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)

	// log.Debugf("token: %v", token)
	log.Debugf("token created, expires: %d diff from now: %d", claims.StandardClaims.ExpiresAt, claims.StandardClaims.ExpiresAt-time.Now().Unix())

	// token -> string. Only server knows this secret (foobar).
	ss, err := token.SignedString([]byte(cfg.Cfg.JWT.Secret))
	// ss, err := token.SignedString([]byte("testing"))
	if ss == "" || err != nil {
		log.Errorf("signed token error: %s", err)
	}
	if cfg.Cfg.JWT.Compress {
		ss, err = compressAndEncodeTokenString(ss)
		if ss == "" || err != nil {
			log.Errorf("compressed token error: %s", err)
		}
	}
	return ss
}

// TokenIsValid gett better error reporting
func TokenIsValid(token *jwt.Token, err error) bool {
	if token.Valid {
		return true
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			log.Errorf("token malformed")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			log.Errorf("token expired %s", err)
		} else {
			log.Errorf("token unknown error")
		}
	} else {
		log.Errorf("token unknown error")
	}
	return false
}

// SiteInToken searches does the token contain the site?
func SiteInToken(site string, token *jwt.Token) bool {
	if claims, ok := token.Claims.(*VouchClaims); ok {
		log.Debugf("site %s claim %v", site, claims)
		if claims.SiteInClaims(site) {
			return true
		}
	}
	log.Errorf("site %s not found in token", site)
	return false
}

// ParseTokenString converts signed token to jwt struct
func ParseTokenString(tokenString string) (*jwt.Token, error) {
	log.Debugf("tokenString length: %d", len(tokenString))
	if cfg.Cfg.JWT.Compress {
		tokenString = decodeAndDecompressTokenString(tokenString)
		log.Debugf("decompressed tokenString length %d", len(tokenString))
	}

	return jwt.ParseWithClaims(tokenString, &VouchClaims{}, func(token *jwt.Token) (interface{}, error) {
		// return jwt.ParseWithClaims(tokenString, &VouchClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod("HS256") {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(cfg.Cfg.JWT.Secret), nil
	})

}

// SiteInClaims does the claim contain the value?
func (claims *VouchClaims) SiteInClaims(site string) bool {
	for _, s := range claims.Sites {
		if strings.Contains(site, s) {
			log.Debugf("site %s is found for claims.Site %s", site, s)
			return true
		}
	}
	return false
}

// PTokenClaims get all the claims
func PTokenClaims(ptoken *jwt.Token) (*VouchClaims, error) {
	// func PTokenClaims(ptoken *jwt.Token) (VouchClaims, error) {
	// return ptoken.Claims, nil

	// return ptoken.Claims.(*VouchClaims), nil
	ptokenClaims, ok := ptoken.Claims.(*VouchClaims)
	if !ok {
		log.Debugf("failed claims: %v %v", ptokenClaims, ptoken.Claims)
		return ptokenClaims, errors.New("cannot parse claims")
	}
	log.Debugf("*ptokenCLaims: %v", *ptokenClaims)
	return ptokenClaims, nil
}

func decodeAndDecompressTokenString(encgzipss string) string {

	var gzipss []byte
	// gzipss, err := url.QueryUnescape(encgzipss)
	gzipss, err := base64.URLEncoding.DecodeString(encgzipss)
	if err != nil {
		log.Debugf("Error in Base64decode: %v", err)
	}

	breader := bytes.NewReader(gzipss)
	zr, err := gzip.NewReader(breader)
	if err != nil {
		log.Debugf("Error reading gzip data: %v", err)
		return ""
	}
	if err := zr.Close(); err != nil {
		log.Debugf("Error decoding token: %v", err)
	}
	ss, _ := ioutil.ReadAll(zr)
	return string(ss)
}

func compressAndEncodeTokenString(ss string) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(ss)); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}

	ret := base64.URLEncoding.EncodeToString(buf.Bytes())
	// ret := url.QueryEscape(buf.String())
	log.Debugf("token compressed: was %d bytes, now %d", len(ss), len(ret))
	return ret, nil
}

// FindJWT look for JWT in Cookie, JWT Header, Authorization Header (OAuth2 Bearer Token)
// and Query String in that order
func FindJWT(r *http.Request) string {
	jwt, err := cookie.Cookie(r)
	if err == nil {
		logger.Debug("jwt found in cookie")
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

// ClaimsFromJWT parse the jwt and return the claims
func ClaimsFromJWT(jwt string) (*VouchClaims, error) {
	var claims *VouchClaims

	jwtParsed, err := ParseTokenString(jwt)
	if err != nil {
		return nil, err
	}

	claims, err = PTokenClaims(jwtParsed)
	if err != nil {
		// claims = jwtmanager.PTokenClaims(jwtParsed)
		// if claims == &jwtmanager.VouchClaims{} {
		return nil, err
	}
	return claims, nil
}
