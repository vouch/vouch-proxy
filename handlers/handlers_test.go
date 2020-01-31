package handlers

import (
	"encoding/json"
	"golang.org/x/oauth2"
	"net/http"
	"regexp"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/structs"

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

var (
	user            *structs.User
	token           = &oauth2.Token{AccessToken: "123"}
	mockedResponses = []FunResponsePair{}
	client          = &http.Client{Transport: &Transport{}}
)

func init() {
	setUp()
}

func setUp() {
	cfg.InitForTestPurposesWithProvider("github")

	cfg.Cfg.AllowAllUsers = false
	cfg.Cfg.WhiteList = make([]string, 0)
	cfg.Cfg.Org = ""
	cfg.Cfg.TeamWhiteList = make([]string, 0)
	cfg.Cfg.Domains = []string{"domain1"}

	domains.Refresh()

	mockedResponses = []FunResponsePair{}

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
	cfg.Cfg.Org = "testorg"
	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "team2", "team1")

	user.TeamMemberships = append(user.TeamMemberships, "team3")
	user.TeamMemberships = append(user.TeamMemberships, "team1")
	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegativeByTeam(t *testing.T) {
	setUp()
	cfg.Cfg.Org = "testorg"
	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "team1")

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
		Login:   "login",
		Picture: "avatar-url",
	})
	mockResponse(urlEquals(cfg.GenOAuth.UserInfoURL+token.AccessToken), http.StatusOK, map[string]string{}, userInfoContent)

	cfg.Cfg.Org = "myorg"

	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "myteam")

	mockResponse(regexMatcher(".*"), http.StatusOK, map[string]string{}, []byte("{\"state\": \"active\"}"))

	err := getUserInfoFromGitHub(client, user, &structs.CustomClaims{}, token)

	assert.Nil(t, err)
	assert.Equal(t, "login", user.Username)
	assert.Equal(t, []string{"myteam"}, user.TeamMemberships)
}
