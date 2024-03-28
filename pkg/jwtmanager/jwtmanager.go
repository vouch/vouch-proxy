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

	jwt "github.com/golang-jwt/jwt"
	"go.uber.org/zap"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

const comma = ","

// VouchClaims jwt Claims specific to vouch
type VouchClaims struct {
	Sub          string `json:"sub"`
	Username     string `json:"username"`
	CustomClaims map[string]interface{}
	PAccessToken string
	PIdToken     string
	jwt.StandardClaims
}

// StandardClaims jwt.StandardClaims implementation
var StandardClaims jwt.StandardClaims

var logger *zap.Logger
var log *zap.SugaredLogger
var aud string

// Configure see main.go configure()
func Configure() {
	log = cfg.Logging.Logger
	logger = cfg.Logging.FastLogger
	cacheConfigure()
	aud = audience()
	StandardClaims = jwt.StandardClaims{
		Issuer:   cfg.Cfg.JWT.Issuer,
		Audience: aud,
	}
}

// `aud` of the issued JWT https://tools.ietf.org/html/rfc7519#section-4.1.3
func audience() string {
	aud := make([]string, 0)
	// TODO: the Sites that end up in the JWT come from here
	// if we add fine grain ability (ACL?) to the equation
	// then we're going to have to add something fancier here
	for i := 0; i < len(cfg.Cfg.Domains); i++ {
		aud = append(aud, cfg.Cfg.Domains[i])
	}
	if cfg.Cfg.Cookie.Domain != "" {
		aud = append(aud, cfg.Cfg.Cookie.Domain)
	}
	return strings.Join(aud, comma)
}

// NewVPJWT issue a signed Vouch Proxy JWT for a user
func NewVPJWT(u structs.User, customClaims structs.CustomClaims, ptokens structs.PTokens) (string, error) {
	// User`token`
	// u.PrepareUserData()
	claims := VouchClaims{
		u.Sub,
		u.Username,
		customClaims.Claims,
		ptokens.PAccessToken,
		ptokens.PIdToken,
		StandardClaims,
	}

	claims.Audience = aud
	claims.ExpiresAt = time.Now().Add(time.Minute * time.Duration(cfg.Cfg.JWT.MaxAge)).Unix()

	// https://github.com/vouch/vouch-proxy/issues/287
	if cfg.Cfg.Headers.AccessToken == "" {
		claims.PAccessToken = ""
	}

	if cfg.Cfg.Headers.IDToken == "" {
		claims.PIdToken = ""
	}

	// https://godoc.org/github.com/golang-jwt/jwt#NewWithClaims
	token := jwt.NewWithClaims(jwt.GetSigningMethod(cfg.Cfg.JWT.SigningMethod), claims)
	// log.Debugf("token: %v", token)
	log.Debugf("token created, expires: %d diff from now: %d", claims.StandardClaims.ExpiresAt, claims.StandardClaims.ExpiresAt-time.Now().Unix())

	key, err := cfg.SigningKey()
	if err != nil {
		log.Errorf("%s", err)
	}

	ss, err := token.SignedString(key)
	if ss == "" || err != nil {
		return "", fmt.Errorf("New JWT: signed token error: %s", err)
	}
	if cfg.Cfg.JWT.Compress {
		ss, err = compressAndEncodeTokenString(ss)
		if ss == "" || err != nil {
			return "", fmt.Errorf("New JWT: compressed token error: %w", err)
		}
	}
	return ss, nil
}

// SiteInToken searches does the token contain the site?
func SiteInToken(site string, token *jwt.Token) bool {
	if claims, ok := token.Claims.(*VouchClaims); ok {
		log.Debugf("site %s claim %v", site, claims)
		if claims.SiteInAudience(site) {
			return true
		}
	}
	log.Errorf("site %s not found in token audience", site)
	return false
}

// ParseTokenString converts signed token to jwt struct
func ParseTokenString(tokenString string) (*jwt.Token, error) {
	log.Debugf("tokenString length: %d", len(tokenString))
	if cfg.Cfg.JWT.Compress {
		tokenString = decodeAndDecompressTokenString(tokenString)
		log.Debugf("decompressed tokenString length %d", len(tokenString))
	}

	key, err := cfg.DecryptionKey()
	if err != nil {
		log.Errorf("%s", err)
	}

	return jwt.ParseWithClaims(tokenString, &VouchClaims{}, func(token *jwt.Token) (interface{}, error) {
		// return jwt.ParseWithClaims(tokenString, &VouchClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod(cfg.Cfg.JWT.SigningMethod) {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return key, nil
	})

}

// SiteInAudience does the claim contain the value?
func (claims *VouchClaims) SiteInAudience(site string) bool {
	for _, s := range strings.Split(aud, comma) {
		if strings.Contains(site, s) {
			log.Debugf("site %s is found for claims.Audience %s", site, s)
			return true
		}
	}
	return false
}

// PTokenClaims get all the claims
func PTokenClaims(ptoken *jwt.Token) (*VouchClaims, error) {
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
