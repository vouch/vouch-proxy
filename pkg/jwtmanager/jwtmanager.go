package jwtmanager

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"git.fs.bnf.net/bnfinet/lasso/pkg/cfg"
	"git.fs.bnf.net/bnfinet/lasso/pkg/structs"
	log "github.com/Sirupsen/logrus"

	jwt "github.com/dgrijalva/jwt-go"
)

const numSites = 1

// LassoClaims jwt Claims specific to lasso
type LassoClaims struct {
	Email string           `json:"email"`
	Sites [numSites]string `json:"sites"` // tempting to make this a map but the array is fewer characters in the jwt
	jwt.StandardClaims
}

// StandardClaims jwt.StandardClaims implimentation
var StandardClaims jwt.StandardClaims

// Sites just testing
var Sites [numSites]string

func init() {
	StandardClaims = jwt.StandardClaims{
		Issuer: cfg.Cfg.JWT.Issuer,
	}
	for i := 0; i < numSites; i++ {
		// Sites[i] = fmt.Sprintf("site%d.bnf.net", i)
		Sites[i] = "naga.bnf.net"
	}
}

// CreateUserTokenString converts user to signed jwt
func CreateUserTokenString(u structs.User) string {
	// User`token`
	claims := LassoClaims{
		u.Email,
		Sites,
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
	ss, err := token.SignedString(cfg.Cfg.JWT.Secret)
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

// TokenClaimsIncludeSite searches does the token contain the site?
func TokenClaimsIncludeSite(token *jwt.Token, site string) bool {
	if claims, ok := token.Claims.(*LassoClaims); ok {
		for _, s := range claims.Sites {
			if s == site {
				return true
			}
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

	return jwt.ParseWithClaims(tokenString, &LassoClaims{}, func(token *jwt.Token) (interface{}, error) {
		// return jwt.ParseWithClaims(tokenString, &LassoClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod("HS256") {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return cfg.Cfg.JWT.Secret, nil
	})

}

// PTokenToEmail returns the Email in the validated ptoken
func PTokenToEmail(ptoken *jwt.Token) (string, error) {

	ptokenClaims, ok := ptoken.Claims.(*LassoClaims)
	if ptokenClaims == nil || !ok {
		return "", errors.New("cannot parse claims")
	}
	return ptokenClaims.Email, nil
}

func decodeAndDecompressTokenString(encgzipss string) string {

	var gzipss []byte
	// gzipss, err := url.QueryUnescape(encgzipss)
	gzipss, err := base64.URLEncoding.DecodeString(encgzipss)
	if err != nil {
		log.Fatal(err)
	}

	breader := bytes.NewReader(gzipss)
	zr, err := gzip.NewReader(breader)
	if err != nil {
		log.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		log.Fatal(err)
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
