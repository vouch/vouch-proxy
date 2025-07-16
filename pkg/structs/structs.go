/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package structs

import "strconv"

// CustomClaims Temporary struct storing custom claims until JWT creation.
type CustomClaims struct {
	Claims map[string]interface{}
}

// UserI each *User struct must prepare the data for being placed in the JWT
type UserI interface {
	PrepareUserData()
}

// User is inherited.
type User struct {
	// TODO: set Provider here so that we can pass it to db
	// populated by db (via mapstructure) or from provider (via json)
	// Provider   string `json:"provider",mapstructure:"provider"`
	Username   string `json:"username" mapstructure:"username"`
	Name       string `json:"name" mapstructure:"name"`
	Email      string `json:"email" mapstructure:"email"`
	CreatedOn  int64  `json:"createdon"`
	LastUpdate int64  `json:"lastupdate"`
	// don't populate ID from json https://github.com/vouch/vouch-proxy/issues/185
	ID int `json:"-" mapstructure:"id"`
	// jwt.StandardClaims

	TeamMemberships []string
}

// PrepareUserData implement PersonalData interface
func (u *User) PrepareUserData() {
	if u.Username == "" {
		u.Username = u.Email
	}
}

// AzureUser is a retrieved and authenticated user from Azure AD
type AzureUser struct {
	User
	Sub               string `json:"sub"`
	UPN               string `json:"upn"`
	PreferredUsername string `json:"preferred_username"`
}

// PrepareUserData implement PersonalData interface
func (u *AzureUser) PrepareUserData() {
	// AzureAD uses the 'upn' (UserPrincipleName) field to store the email address of the user
	// See https://docs.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-userprincipalname

	if u.Username == "" {
		u.Username = u.UPN
	}

	if u.Username == "" {
		u.Username = u.PreferredUsername
	}

	if u.Email == "" {
		u.Email = u.UPN
	}
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

// ADFSUser Active Directory user record
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

// GitHubTeamMembershipState for GitHub team api call
type GitHubTeamMembershipState struct {
	State string `json:"state"`
}

// PrepareUserData implement PersonalData interface
func (u *GitHubUser) PrepareUserData() {
	// always use the u.Login as the u.Username
	u.Username = u.Login
}

// HomeAssistantUser
type HomeAssistantUser struct {
	User
	IsAdmin bool `json:"is_admin"`
	IsOwner bool `json:"is_owner"`
}

func (u *HomeAssistantUser) PrepareUserData() {
	u.Username = u.Name
}

// IndieAuthUser see indieauth.net
type IndieAuthUser struct {
	User
	URL string `json:"me"`
}

// PrepareUserData implement PersonalData interface
func (u *IndieAuthUser) PrepareUserData() {
	u.Username = u.URL
}

// Contact used for OpenStaxUser
type Contact struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Verified bool   `json:"is_verified"`
}

// OpenStaxUser is a retrieved and authenticated user from OpenStax Accounts
type OpenStaxUser struct {
	User
	Contacts []Contact `json:"contact_infos"`
}

// PrepareUserData implement PersonalData interface
func (u *OpenStaxUser) PrepareUserData() {
	if u.Email == "" {
		// assuming first contact of type "EmailAddress"
		for _, c := range u.Contacts {
			if c.Type == "EmailAddress" && c.Verified {
				u.Email = c.Value
				break
			}
		}
	}
}

// Ocs used for NextcloudUser
type Ocs struct {
	Data struct {
		UserID string `json:"id"`
		Email  string `json:"email"`
	} `json:"data"`
}

// NextcloudUser User of Nextcloud retreived from ocs endpoint
type NextcloudUser struct {
	User
	Ocs Ocs `json:"ocs"`
}

// PrepareUserData NextcloudUser
func (u *NextcloudUser) PrepareUserData() {
	if u.Username == "" {
		u.Username = u.Ocs.Data.UserID
		u.Email = u.Ocs.Data.Email
	}
}

// AlibabaUser Aliyun
type AlibabaUser struct {
	User
	Data AliData `json:"data"`
	// jwt.StandardClaims
}

// PrepareUserData implement PersonalData interface
func (u *AlibabaUser) PrepareUserData() {
	u.Username = u.Data.Username
	u.Name = u.Data.Nickname
	u.Email = u.Data.Email
	id, _ := strconv.Atoi(u.Data.ID)
	u.ID = id
}

// AliData `data` subobject of Alibaba User response
// https://github.com/vouch/vouch-proxy/issues/344
type AliData struct {
	Sub      string `json:"sub"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	ID       string `json:"ou_id"`
	Phone    string `json:"phone_number"`
	OuName   string `json:"ou_name"`
}

// Team has members and provides acess to sites
type Team struct {
	Name       string   `json:"name" mapstructure:"name"`
	Members    []string `json:"members" mapstructure:"members"` // just the emails
	Sites      []string `json:"sites" mapstructure:"sites"`     // just the domains
	CreatedOn  int64    `json:"createdon" mapstructure:"createdon"`
	LastUpdate int64    `json:"lastupdate" mapstructure:"lastupdate"`
	ID         int      `json:"id" mapstructure:"id"`
}

// Site is the basic unit of auth
type Site struct {
	Domain     string `json:"domain"`
	CreatedOn  int64  `json:"createdon"`
	LastUpdate int64  `json:"lastupdate"`
	ID         int    `json:"id" mapstructure:"id"`
}

// PTokens provider tokens (from the IdP)
type PTokens struct {
	PAccessToken string
	PIdToken     string
}
