package jwtmanager

import (
	"errors"
	"fmt"
	"time"

	cfg "git.fs.bnf.net/bnfinet/lasso/lib/cfg"
	structs "git.fs.bnf.net/bnfinet/lasso/lib/structs"
	log "github.com/Sirupsen/logrus"

	jwt "github.com/dgrijalva/jwt-go"
)

type LassoClaims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

var Key = []byte(cfg.Get("jwt.secret"))
var StandardClaims jwt.StandardClaims

func init() {
	StandardClaims = jwt.StandardClaims{
		Issuer: "lasso",
	}
}

// CreateUserTokenString
func CreateUserTokenString(u structs.User) string {
	// User`token`
	claims := LassoClaims{
		u.Email,
		StandardClaims,
	}
	claims.StandardClaims.ExpiresAt = time.Now().Add(time.Hour * 1).Unix()

	// https://godoc.org/github.com/dgrijalva/jwt-go#NewWithClaims
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)

	log.Debugf("token: %v", token)

	// token -> string. Only server knows this secret (foobar).
	ss, err := token.SignedString(Key)
	if err != nil {
		log.Debugf("%v %s", ss, err)
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
			log.Errorf("token expired")
		} else {
			log.Errorf("token unknown error")
		}
	} else {
		log.Errorf("token unknown error")
	}
	return false
}

func ParseTokenString(tokenString string) (*jwt.Token, error) {

	ptoken, err := jwt.ParseWithClaims(tokenString, &LassoClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.GetSigningMethod("HS256") {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// if !tokenString {
		// 	log.Error(token)
		// 	return nil, fmt.Errorf("invalid token")
		// }
		return Key, nil
	})
	if !tokenIsValid(ptoken, err) {
		return nil, errors.New("token is not valid")
	}
	return ptoken, err

}

// PTokenEmail returns the Email in the validated ptoken
func PTokenToEmail(ptoken *jwt.Token) (string, error) {

	ptokenClaims, ok := ptoken.Claims.(*LassoClaims)
	if !ok {
		return "", errors.New("cannot parse claims")
	}
	return ptokenClaims.Email, nil
}
