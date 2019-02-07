package jwtmanager

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"

	jwt "github.com/dgrijalva/jwt-go"
)

// const numSites = 2

// VouchClaims jwt Claims specific to vouch
type VouchClaims struct {
	Username    string   `json:"username"`
	Sites       []string `json:"sites"` // tempting to make this a map but the array is fewer characters in the jwt
	IDToken     string   `json:"id_token"`
	AccessToken string   `json:"access_token"`
	jwt.StandardClaims
}

// StandardClaims jwt.StandardClaims implimentation
var StandardClaims jwt.StandardClaims

// Sites just testing
var Sites []string

func init() {
	StandardClaims = jwt.StandardClaims{
		Issuer: cfg.Cfg.JWT.Issuer,
	}
	Sites = make([]string, 0)

	// TODO: the Sites that end up in the JWT come from here
	// if we add fine grain ability (ACL?) to the equation
	// then we're going to have to add something fancier here
	for i := 0; i < len(cfg.Cfg.Domains); i++ {
		Sites = append(Sites, cfg.Cfg.Domains[i])
	}
}

// CreateUserTokenString converts user to signed jwt
func CreateUserTokenString(u structs.User) string {
	// User`token`
	// u.PrepareUserData()
	claims := VouchClaims{
		u.Username,
		Sites,
		u.IDToken,
		u.AccessToken,
		StandardClaims,
	}

	claims.StandardClaims.ExpiresAt = time.Now().Add(time.Minute * time.Duration(cfg.Cfg.JWT.MaxAge)).Unix()

	// https://godoc.org/github.com/dgrijalva/jwt-go#NewWithClaims
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	log.Debugf("token: %v", token)

	// log.Debugf("token: %v", token)
	log.Debugf("token expires: %d", claims.StandardClaims.ExpiresAt)
	log.Debugf("diff from now: %d", claims.StandardClaims.ExpiresAt-time.Now().Unix())

	// token -> string. Only server knows this secret (foobar).
	ss, err := token.SignedString([]byte(cfg.Cfg.JWT.Secret))
	// ss, err := token.SignedString([]byte("testing"))
	if ss == "" || err != nil {
		log.Errorf("signed token error: %s", err)
	}
	if cfg.Cfg.JWT.Compress {
		return compressAndEncodeTokenString(ss)
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
		if SiteInClaims(site, claims) {
			return true
		}
	}
	log.Errorf("site %s not found in token", site)
	return false
}

// ParseTokenString converts signed token to jwt struct
func ParseTokenString(tokenString string) (*jwt.Token, error) {
	log.Debugf("tokenString %s", tokenString)
	if cfg.Cfg.JWT.Compress {
		tokenString = decodeAndDecompressTokenString(tokenString)
		log.Debugf("decompressed tokenString %s", tokenString)
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
func SiteInClaims(site string, claims *VouchClaims) bool {
	for _, s := range claims.Sites {
		if strings.Contains(site, s) {
			log.Debugf("site %s is found for claims.Site %s", site, s)
			return true
		}
	}
	return false
}

// PTokenClaims get all the claims
// TODO HERE there's something wrong with claims parsing, probably related to VouchClaims not being a pointer
func PTokenClaims(ptoken *jwt.Token) (VouchClaims, error) {
	// func PTokenClaims(ptoken *jwt.Token) (VouchClaims, error) {
	// return ptoken.Claims, nil

	// return ptoken.Claims.(*VouchClaims), nil
	ptokenClaims, ok := ptoken.Claims.(*VouchClaims)
	if !ok {
		log.Debugf("failed claims: %v %v", ptokenClaims, ptoken.Claims)
		return *ptokenClaims, errors.New("cannot parse claims")
	}
	log.Debugf("*ptokenCLaims: %v", *ptokenClaims)
	return *ptokenClaims, nil
}

// PTokenToUsername returns the Username in the validated ptoken
func PTokenToUsername(ptoken *jwt.Token) (string, error) {
	return ptoken.Claims.(*VouchClaims).Username, nil

	// var ptokenClaims VouchClaims
	// ptokenClaims, err := PTokenClaims(ptoken)
	// if err != nil {
	// 	log.Error(err)
	// 	return "", err
	// }
	// return ptokenClaims.Username, nil
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

func compressAndEncodeTokenString(ss string) string {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(ss)); err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}

	ret := base64.URLEncoding.EncodeToString(buf.Bytes())
	// ret := url.QueryEscape(buf.String())
	log.Debugf("compressed string: %s", ret)
	return ret
}
