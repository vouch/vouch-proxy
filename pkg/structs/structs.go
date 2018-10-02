package structs

// User is inherited.
type User struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	CreatedOn  int64  `json:"createdon"`
	LastUpdate int64  `json:"lastupdate"`
	ID         int    `json:"id",mapstructure:"id"`
	// jwt.StandardClaims
}

// GoogleUser is a retrieved and authentiacted user from Google.
// unused!
type GoogleUser struct {
	User
	Sub           string `json:"sub"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
	HostDomain    string `json:"hd"`
	// jwt.StandardClaims
}

// GithubUser is a retrieved and authentiacted user from Github.
type GithubUser struct {
	User
	Login   string `json:"login"`
	Picture string `json:"avatar_url"`
	// jwt.StandardClaims
}

// GenericOauth provides endoint for access
type GenericOauth struct {
	ClientID        string   `mapstructure:"client_id"`
	ClientSecret    string   `mapstructure:"client_secret"`
	AuthURL         string   `mapstructure:"auth_url"`
	TokenURL        string   `mapstructure:"token_url"`
	RedirectURL     string   `mapstructure:"callback_url"`
	RedirectURLs    []string `mapstructure:"callback_urls"`
	Scopes          []string `mapstructure:"scopes"`
	UserInfoURL     string   `mapstructure:"user_info_url"`
	Provider        string   `mapstructure:"provider"`
	PreferredDomain string   `mapstructre:"preferredDomain"`
}

// Team has members and provides acess to sites
type Team struct {
	Name       string   `json:"name",mapstructure:"name"`
	Members    []string `json:"members",mapstructure:"members"` // just the emails
	Sites      []string `json:"sites",mapstructure:"sites"`     // just the domains
	CreatedOn  int64    `json:"createdon",mapstructure:"createdon"`
	LastUpdate int64    `json:"lastupdate",mapstructure:"lastupdate"`
	ID         int      `json:"id",mapstructure:"id"`
}

// Site is the basic unit of auth
type Site struct {
	Domain     string `json:"domain"`
	CreatedOn  int64  `json:"createdon"`
	LastUpdate int64  `json:"lastupdate"`
	ID         int    `json:"id",mapstructure:"id"`
}
