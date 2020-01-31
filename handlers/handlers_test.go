package handlers

import (
	"encoding/json"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
	"net/http"
	"regexp"

	mockhttp "github.com/karupanerura/go-mock-http-response"
	"github.com/stretchr/testify/assert"
	"testing"
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

func assertUrlCalled(t *testing.T, url string) {
	found := false
	for _, requested_url := range requests {
		if requested_url == url {
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

func init() {
	setUp()
}

func setUp() {
	cfg.InitForTestPurposesWithProvider("github")

	cfg.Cfg.AllowAllUsers = false
	cfg.Cfg.WhiteList = make([]string, 0)
	cfg.Cfg.TeamWhiteList = make([]string, 0)
	cfg.Cfg.Domains = []string{"domain1"}

	domains.Refresh()

	mockedResponses = []FunResponsePair{}
	requests = make([]string, 0)

	user = &structs.User{Username: "testuser", Email: "test@example.com"}
}

func TestVerifyUserPositiveUserInWhiteList(t *testing.T) {
	setUp()
	cfg.Cfg.WhiteList = append(cfg.Cfg.WhiteList, user.Username)

	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveAllowAllUsers(t *testing.T) {
	setUp()
	cfg.Cfg.AllowAllUsers = true

	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByEmail(t *testing.T) {
	setUp()
	cfg.Cfg.Domains = append(cfg.Cfg.Domains, "example.com")
	domains.Refresh()

	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByTeam(t *testing.T) {
	setUp()
	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team2", "org1/team1")

	user.TeamMemberships = append(user.TeamMemberships, "org1/team3")
	user.TeamMemberships = append(user.TeamMemberships, "org1/team1")
	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegativeByTeam(t *testing.T) {
	setUp()
	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team1")

	ok, err := VerifyUser(*user)
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestVerifyUserPositiveNoDomainsConfigured(t *testing.T) {
	setUp()
	cfg.Cfg.Domains = make([]string, 0)

	ok, err := VerifyUser(*user)

	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegative(t *testing.T) {
	setUp()

	ok, err := VerifyUser(*user)

	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestGetTeamMembershipStateFromGitHubActive(t *testing.T) {
	setUp()
	mockResponse(regexMatcher(".*"), http.StatusOK, map[string]string{}, []byte("{\"state\": \"active\"}"))

	err, isMember := getTeamMembershipStateFromGitHub(client, user, "org1", "team1", token)

	assert.Nil(t, err)
	assert.True(t, isMember)
}

func TestGetTeamMembershipStateFromGitHubInactive(t *testing.T) {
	setUp()
	mockResponse(regexMatcher(".*"), http.StatusOK, map[string]string{}, []byte("{\"state\": \"inactive\"}"))

	err, isMember := getTeamMembershipStateFromGitHub(client, user, "org1", "team1", token)

	assert.Nil(t, err)
	assert.False(t, isMember)
}

func TestGetTeamMembershipStateFromGitHubNotAMember(t *testing.T) {
	setUp()
	mockResponse(regexMatcher(".*"), http.StatusNotFound, map[string]string{}, []byte(""))

	err, isMember := getTeamMembershipStateFromGitHub(client, user, "org1", "team1", token)

	assert.Nil(t, err)
	assert.False(t, isMember)
}

func TestGetOrgMembershipStateFromGitHubNotFound(t *testing.T) {
	setUp()
	mockResponse(regexMatcher(".*"), http.StatusNotFound, map[string]string{}, []byte(""))

	err, isMember := getOrgMembershipStateFromGitHub(client, user, "myorg", token)

	assert.Nil(t, err)
	assert.False(t, isMember)

	expectedOrgMembershipUrl := "https://api.github.com/orgs/myorg/members/" + user.Username + "?access_token=" + token.AccessToken
	assertUrlCalled(t, expectedOrgMembershipUrl)
}

func TestGetOrgMembershipStateFromGitHubNoOrgAccess(t *testing.T) {
	setUp()
	location := "https://api.github.com/orgs/myorg/public_members/" + user.Username

	mockResponse(regexMatcher(".*orgs/myorg/members.*"), http.StatusFound, map[string]string{"Location": location}, []byte(""))
	mockResponse(regexMatcher(".*orgs/myorg/public_members.*"), http.StatusNoContent, map[string]string{}, []byte(""))

	err, isMember := getOrgMembershipStateFromGitHub(client, user, "myorg", token)

	assert.Nil(t, err)
	assert.True(t, isMember)

	expectedOrgMembershipUrl := "https://api.github.com/orgs/myorg/members/" + user.Username + "?access_token=" + token.AccessToken
	assertUrlCalled(t, expectedOrgMembershipUrl)

	expectedOrgPublicMembershipUrl := "https://api.github.com/orgs/myorg/public_members/" + user.Username
	assertUrlCalled(t, expectedOrgPublicMembershipUrl)
}

func TestGetUserInfoFromGitHub(t *testing.T) {
	setUp()

	userInfoContent, _ := json.Marshal(structs.GitHubUser{
		User: structs.User{
			Username:   "test",
			CreatedOn:  123,
			Email:      "email@example.com",
			ID:         1,
			LastUpdate: 123,
			Name:       "name",
		},
		Login:   "myusername",
		Picture: "avatar-url",
	})
	mockResponse(urlEquals(cfg.GenOAuth.UserInfoURL+token.AccessToken), http.StatusOK, map[string]string{}, userInfoContent)

	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "myOtherOrg", "myorg/myteam")

	mockResponse(regexMatcher(".*teams.*"), http.StatusOK, map[string]string{}, []byte("{\"state\": \"active\"}"))
	mockResponse(regexMatcher(".*members.*"), http.StatusNoContent, map[string]string{}, []byte(""))

	err := getUserInfoFromGitHub(client, user, &structs.CustomClaims{}, token)

	assert.Nil(t, err)
	assert.Equal(t, "myusername", user.Username)
	assert.Equal(t, []string{"myOtherOrg", "myorg/myteam"}, user.TeamMemberships)

	expectedTeamMembershipUrl := "https://api.github.com/orgs/myorg/teams/myteam/memberships/myusername?access_token=" + token.AccessToken
	assertUrlCalled(t, expectedTeamMembershipUrl)
}
