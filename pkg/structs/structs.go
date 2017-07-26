package structs

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
	CreatedOn     int64  `json:"createdon"`
	LastUpdate    int64  `json:"lastupdate"`
	// jwt.StandardClaims
}

// GCredentials google credentials
// loaded from yaml config
type GCredentials struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURLs []string `mapstructure:"callback_urls"`
}

// Team has members and provides acess to sites
type Team struct {
	Name       string   `json:"name",mapstructure:"name"`
	Members    []string `json:"members",mapstructure:"members"` // just the emails
	Sites      []string `json:"sites",mapstructure:"sites"`     // just the domains
	CreatedOn  int64    `json:"createdon",mapstructure:"createdon"`
	LastUpdate int64    `json:"lastupdate",mapstructure:"lastupdate"`
	ID         uint64   `json:"id",mapstructure:"id"`
}

// Site is the basic unit of auth
type Site struct {
	Domain     string `json:"domain"`
	CreatedOn  int64  `json:"createdon"`
	LastUpdate int64  `json:"lastupdate"`
}
