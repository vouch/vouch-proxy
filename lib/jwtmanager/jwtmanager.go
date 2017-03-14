package jwtmanager

import (
	"errors"
	"fmt"
	"time"

	"git.fs.bnf.net/bnfinet/lasso/lib/cfg"
	"git.fs.bnf.net/bnfinet/lasso/lib/structs"
	log "github.com/Sirupsen/logrus"

	jwt "github.com/dgrijalva/jwt-go"
)

// LassoClaims jwt Claims specific to lasso
type LassoClaims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

// StandardClaims jwt.StandardClaims implimentation
var StandardClaims jwt.StandardClaims

func init() {
	StandardClaims = jwt.StandardClaims{
		Issuer: cfg.Cfg.JWT.Issuer,
	}
}

// CreateUserTokenString converts user to signed jwt
func CreateUserTokenString(u structs.User) string {
	// User`token`
	claims := LassoClaims{
		u.Email,
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
	return ss
}

func tokenIsValid(token *jwt.Token, err error) bool {
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

// ParseTokenString converts signed token to jwt struct
func ParseTokenString(tokenString string) (*jwt.Token, error) {
	log.Debugf("tokenString %s", tokenString)

	// ptoken, err := jwt.ParseWithClaims(tokenString, &LassoClaims{}, func(token *jwt.Token) (interface{}, error) {
	return jwt.ParseWithClaims(tokenString, &LassoClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod("HS256") {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return cfg.Cfg.JWT.Secret, nil
	})
	// if ptoken == nil || !tokenIsValid(ptoken, err) {
	// 	// return nil, errors.New("token is not valid")
	// 	return nil, err
	// }
	// return ptoken, err
}

// PTokenToEmail returns the Email in the validated ptoken
func PTokenToEmail(ptoken *jwt.Token) (string, error) {

	ptokenClaims, ok := ptoken.Claims.(*LassoClaims)
	if ptokenClaims == nil || !ok {
		return "", errors.New("cannot parse claims")
	}
	return ptokenClaims.Email, nil
}
