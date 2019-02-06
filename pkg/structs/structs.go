package structs

// UserI each *User struct must prepare the data for being placed in the JWT
type UserI interface {
	PrepareUserData()
}

// User is inherited.
type User struct {
	// TODO: set Provider here so that we can pass it to db
	// populated by db (via mapstructure) or from provider (via json)
	// Provider   string `json:"provider",mapstructure:"provider"`
	Username    string `json:"username",mapstructure:"username"`
	Name        string `json:"name",mapstructure:"name"`
	Email       string `json:"email",mapstructure:"email"`
	CreatedOn   int64  `json:"createdon"`
	LastUpdate  int64  `json:"lastupdate"`
	ID          int    `json:"id",mapstructure:"id"`
	IDToken     string `json:"id_token",mapstructure:"id_token"`
	AccessToken string `json:"access_token,mapstructure:"id_token"`
	// jwt.StandardClaims
}

// PrepareUserData implement PersonalData interface
func (u *User) PrepareUserData() {
	u.Username = u.Email
}

// GoogleUser is a retrieved and authentiacted user from Google.
// unused!

// TODO: see if these should be pointers to the *User object as per
// https://golang.org/doc/effective_go.html#embedding
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

// PrepareUserData implement PersonalData interface
func (u *GoogleUser) PrepareUserData() {
	u.Username = u.Email
}

type ADFSUser struct {
	User
	Sub string `json:"sub"`
	UPN string `json:"upn"`
	// UniqueName string `json:"unique_name"`
	// PwdExp     string `json:"pwd_exp"`
	// SID        string `json:"sid"`
	// Groups     string `json:"groups"`
	// jwt.StandardClaims
}

// PrepareUserData implement PersonalData interface
func (u *ADFSUser) PrepareUserData() {
	u.Username = u.UPN
}

// GitHubUser is a retrieved and authentiacted user from GitHub.
type GitHubUser struct {
	User
	Login   string `json:"login"`
	Picture string `json:"avatar_url"`
	// jwt.StandardClaims
}

// PrepareUserData implement PersonalData interface
func (u *GitHubUser) PrepareUserData() {
	// always use the u.Login as the u.Username
	u.Username = u.Login
}

type IndieAuthUser struct {
	User
	URL string `json:"me"`
}

func (u *IndieAuthUser) PrepareUserData() {
	u.Username = u.URL
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
