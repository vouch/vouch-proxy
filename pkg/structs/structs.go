package structs

// import (
// 	jwt "github.com/dgrijalva/jwt-go"
// )

// User is a retrieved and authentiacted user.
type User struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
	HostDomain    string `json:"hd"`
	// jwt.StandardClaims
}

// GCredentials google credentials
// loaded from yaml config
type GCredentials struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"callback_url"`
}
