package cfg

import (
	"io/ioutil"

	securerandom "github.com/theckman/go-securerandom"
)

func getOrGenerateJWTSecret() string {
	b, err := ioutil.ReadFile(secretFile)
	if err == nil {
		log.Info("jwt.secret read from " + secretFile)
	} else {
		// then generate a new secret and store it in the file
		log.Debug(err)
		log.Info("jwt.secret not found in " + secretFile)
		log.Warn("generating random jwt.secret and storing it in " + secretFile)

		// make sure to create 256 bits for the secret
		// see https://github.com/vouch/vouch-proxy/issues/54
		rstr, err := securerandom.Base64OfBytes(base64Bytes)
		if err != nil {
			log.Fatal(err)
		}
		b = []byte(rstr)
		err = ioutil.WriteFile(secretFile, b, 0600)
		if err != nil {
			log.Debug(err)
		}
	}
	return string(b)
}
