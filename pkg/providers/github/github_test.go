/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package github

import (
	"net/http"
	"regexp"
	"testing"

	mockhttp "github.com/karupanerura/go-mock-http-response"
	"github.com/stretchr/testify/assert"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
)

type ReqMatcher func(*http.Request) bool

type FunResponsePair struct {
	matcher  ReqMatcher
	response *mockhttp.ResponseMock
}

type Transport struct {
	MockError error
}

func (c *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.MockError != nil {
		return nil, c.MockError
	}
	for _, p := range mockedResponses {
		if p.matcher(req) {
			requests = append(requests, req.URL.String())
			return p.response.MakeResponse(req), nil
		}
	}
	return nil, nil
}

func mockResponse(fun ReqMatcher, statusCode int, headers map[string]string, body []byte) {
	mockedResponses = append(mockedResponses, FunResponsePair{matcher: fun, response: mockhttp.NewResponseMock(statusCode, headers, body)})
}

func regexMatcher(expr string) ReqMatcher {
	return func(r *http.Request) bool {
		matches, _ := regexp.Match(expr, []byte(r.URL.String()))
		return matches
	}
}

func urlEquals(value string) ReqMatcher {
	return func(r *http.Request) bool {
		return r.URL.String() == value
	}
}

func assertURLCalled(t *testing.T, url string) {
	found := false
	for _, requestedURL := range requests {
		if requestedURL == url {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected %s to have been called, but got only %s", url, requests)
}

var (
	user            *structs.User
	token           = &oauth2.Token{AccessToken: "123"}
	mockedResponses = []FunResponsePair{}
	requests        []string
	client          = &http.Client{Transport: &Transport{}}
)

func setUp() {
	log = cfg.Logging.Logger
	cfg.InitForTestPurposesWithProvider("github")

	cfg.Cfg.AllowAllUsers = false
	cfg.Cfg.WhiteList = make([]string, 0)
	cfg.Cfg.TeamWhiteList = make([]string, 0)
	cfg.Cfg.Domains = []string{"domain1"}

	domains.Configure()

	mockedResponses = []FunResponsePair{}
	requests = make([]string, 0)

	user = &structs.User{Username: "testuser", Email: "test@example.com"}
}

func TestGetTeamMembershipStateFromGitHubActive(t *testing.T) {
	setUp()
	mockResponse(regexMatcher(".*"), http.StatusOK, map[string]string{}, []byte("{\"state\": \"active\"}"))

	isMember, err := getTeamMembershipStateFromGitHub(client, user, "org1", "team1", token)

	assert.Nil(t, err)
	assert.True(t, isMember)
}

func TestGetTeamMembershipStateFromGitHubInactive(t *testing.T) {
	setUp()
	mockResponse(regexMatcher(".*"), http.StatusOK, map[string]string{}, []byte("{\"state\": \"inactive\"}"))

	isMember, err := getTeamMembershipStateFromGitHub(client, user, "org1", "team1", token)

	assert.Nil(t, err)
	assert.False(t, isMember)
}

func TestGetTeamMembershipStateFromGitHubNotAMember(t *testing.T) {
	setUp()
	mockResponse(regexMatcher(".*"), http.StatusNotFound, map[string]string{}, []byte(""))

	isMember, err := getTeamMembershipStateFromGitHub(client, user, "org1", "team1", token)

	assert.Nil(t, err)
	assert.False(t, isMember)
}

func TestGetOrgMembershipStateFromGitHubNotFound(t *testing.T) {
	setUp()
	mockResponse(regexMatcher(".*"), http.StatusNotFound, map[string]string{}, []byte(""))

	isMember, err := getOrgMembershipStateFromGitHub(client, user, "myorg", token)

	assert.Nil(t, err)
	assert.False(t, isMember)

	expectedOrgMembershipURL := "https://api.github.com/orgs/myorg/members/" + user.Username + "?access_token=" + token.AccessToken
	assertURLCalled(t, expectedOrgMembershipURL)
}

func TestGetOrgMembershipStateFromGitHubNoOrgAccess(t *testing.T) {
	setUp()
	location := "https://api.github.com/orgs/myorg/public_members/" + user.Username

	mockResponse(regexMatcher(".*orgs/myorg/members.*"), http.StatusFound, map[string]string{"Location": location}, []byte(""))
	mockResponse(regexMatcher(".*orgs/myorg/public_members.*"), http.StatusNoContent, map[string]string{}, []byte(""))

	isMember, err := getOrgMembershipStateFromGitHub(client, user, "myorg", token)

	assert.Nil(t, err)
	assert.True(t, isMember)

	expectedOrgMembershipURL := "https://api.github.com/orgs/myorg/members/" + user.Username + "?access_token=" + token.AccessToken
	assertURLCalled(t, expectedOrgMembershipURL)

	expectedOrgPublicMembershipURL := "https://api.github.com/orgs/myorg/public_members/" + user.Username
	assertURLCalled(t, expectedOrgPublicMembershipURL)
}

func TestGetUserInfo(t *testing.T) {
	setUp()

	// Use JSON directly (instead of populating a struct and converting to JSON) to reduce the chances
	// of a mismatch between what GitHub provides and what is expected.
	userInfoContent := []byte(`
		{
			"avatar_url": "avatar-url",
			"email": "email@example.com",
			"id": 123456789,
			"login": "myusername",
			"name": "name"
		}
	`)
	mockResponse(urlEquals(cfg.GenOAuth.UserInfoURL+token.AccessToken), http.StatusOK, map[string]string{}, userInfoContent)

	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "myOtherOrg", "myorg/myteam")

	mockResponse(regexMatcher(".*teams.*"), http.StatusOK, map[string]string{}, []byte("{\"state\": \"active\"}"))
	mockResponse(regexMatcher(".*members.*"), http.StatusNoContent, map[string]string{}, []byte(""))

	provider := Provider{PrepareTokensAndClient: func(_ *http.Request, _ *structs.PTokens, _ bool, opts ...oauth2.AuthCodeOption) (*http.Client, *oauth2.Token, error) {
		return client, token, nil
	}}
	err := provider.GetUserInfo(nil, user, &structs.CustomClaims{}, &structs.PTokens{})

	assert.Nil(t, err)
	assert.Equal(t, "123456789", user.Sub)
	assert.Equal(t, "myusername", user.Username)
	assert.Equal(t, []string{"myOtherOrg", "myorg/myteam"}, user.TeamMemberships)

	expectedTeamMembershipURL := "https://api.github.com/orgs/myorg/teams/myteam/memberships/myusername?access_token=" + token.AccessToken
	assertURLCalled(t, expectedTeamMembershipURL)
}
