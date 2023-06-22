/*

Copyright 2023 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package openid

import (
	"net/http"
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

func urlEquals(value string) ReqMatcher {
	return func(r *http.Request) bool {
		return r.URL.String() == value
	}
}

var (
	user            *structs.User
	token           = &oauth2.Token{AccessToken: "123"}
	mockedResponses = []FunResponsePair{}
	requests        []string
	client          = &http.Client{Transport: &Transport{}}
)

func setUp(t *testing.T) {
	log = cfg.Logging.Logger
	cfg.InitForTestPurposesWithProvider("openid")

	cfg.Cfg.AllowAllUsers = false
	cfg.Cfg.WhiteList = make([]string, 0)
	cfg.Cfg.TeamWhiteList = make([]string, 0)
	cfg.Cfg.Domains = []string{"domain1"}

	domains.Configure()

	mockedResponses = []FunResponsePair{}
	requests = make([]string, 0)

	user = &structs.User{Username: "testuser", Email: "test@example.com"}

	origPrepareTokensAndClient := prepareTokensAndClient
	t.Cleanup(func() { prepareTokensAndClient = origPrepareTokensAndClient })
	prepareTokensAndClient = func(_ *http.Request, _ *structs.PTokens, _ bool, opts ...oauth2.AuthCodeOption) (*http.Client, *oauth2.Token, error) {
		return client, token, nil
	}
}

func TestGetUserInfo(t *testing.T) {
	setUp(t)

	cfg.GenOAuth.UserInfoURL = "https://some/api/for/info"
	userInfoContent := []byte(`{"id": "1234", "username": "myusername", "email": "my@email.com"}`)
	mockResponse(urlEquals(cfg.GenOAuth.UserInfoURL), http.StatusOK, map[string]string{}, userInfoContent)

	cfg.GenOAuth.UserTeamURL = "https://some/api/for/teams"
	userTeamContent := []byte(`[{"id": "1234567890", "name": "some room name"}, {"id": "xxx-not-relevant", "name": "some other room"}]`)
	mockResponse(urlEquals(cfg.GenOAuth.UserTeamURL), http.StatusOK, map[string]string{}, userTeamContent)

	cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "1234567890", "some-other-team")

	provider := Provider{}
	err := provider.GetUserInfo(nil, user, &structs.CustomClaims{}, &structs.PTokens{})

	assert.Nil(t, err)
	assert.Equal(t, "myusername", user.Username)
	assert.Equal(t, []string{"1234567890"}, user.TeamMemberships)
}
