package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vouch/vouch-proxy/pkg/cookie"

	"github.com/stretchr/testify/assert"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"golang.org/x/oauth2"
)

var (
	token = &oauth2.Token{AccessToken: "123"}
)

func setUp(configFile string) {
	os.Setenv("VOUCH_CONFIG", filepath.Join(os.Getenv("VOUCH_ROOT"), configFile))
	cfg.InitForTestPurposes()

	// cfg.Cfg.AllowAllUsers = false
	// cfg.Cfg.WhiteList = make([]string, 0)
	// cfg.Cfg.TeamWhiteList = make([]string, 0)
	// cfg.Cfg.Domains = []string{"domain1"}

	Configure()

	domains.Configure()
	jwtmanager.Configure()
	cookie.Configure()

}

// init() for TestValidateRequestHandlerWithGroupClaims
// func init() {
// 	cfg.RootDir = "../"
// 	cfg.InitForTestPurposesWithPath("../config/test_config.yml")
// 	Init()
// }

func TestValidateRequestHandlerWithGroupClaims(t *testing.T) {
	// setUp()

	// user := structs.User{
	// 	Username: "test@testing.com",
	// 	Name:     "Test Name",
	// }
	setUp("/config/testing/handler_claims.yml")

	customClaims := structs.CustomClaims{
		Claims: map[string]interface{}{
			"sub": "f:a95afe53-60ba-4ac6-af15-fab870e72f3d:mrtester",
			"groups": []string{
				"Website Users",
				"Test Group",
			},
			"given_name":    "Mister",
			"family_name":   "Tester",
			"email":         "mrtester@test.int",
			"boolean_claim": true,
		},
	}

	tokens := structs.PTokens{
		// PAccessToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRvaXU4In0.eyJzdWIiOiJuZnlmZSIsImF1ZCI6ImltX29pY19jbGllbnQiLCJqdGkiOiJUOU4xUklkRkVzUE45enU3ZWw2eng2IiwiaXNzIjoiaHR0cHM6XC9cL3Nzby5tZXljbG91ZC5uZXQ6OTAzMSIsImlhdCI6MTM5MzczNzA3MSwiZXhwIjoxMzkzNzM3MzcxLCJub25jZSI6ImNiYTU2NjY2LTRiMTItNDU2YS04NDA3LTNkMzAyM2ZhMTAwMiIsImF0X2hhc2giOiJrdHFvZVBhc2praVY5b2Z0X3o5NnJBIn0.g1Jc9DohWFfFG3ppWfvW16ib6YBaONC5VMs8J61i5j5QLieY-mBEeVi1D3vr5IFWCfivY4hZcHtoJHgZk1qCumkAMDymsLGX-IGA7yFU8LOjUdR4IlCPlZxZ_vhqr_0gQ9pCFKDkiOv1LVv5x3YgAdhHhpZhxK6rWxojg2RddzvZ9Xi5u2V1UZ0jukwyG2d4PRzDn7WoRNDGwYOEt4qY7lv_NO2TY2eAklP-xYBWu0b9FBElapnstqbZgAXdndNs-Wqp4gyQG5D0owLzxPErR9MnpQfgNcai-PlWI_UrvoopKNbX0ai2zfkuQ-qh6Xn8zgkiaYDHzq4gzwRfwazaqA",
		// PIdToken:     "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRvaXU4In0.eyJzdWIiOiJuZnlmZSIsImF1ZCI6ImltX29pY19jbGllbnQiLCJqdGkiOiJUOU4xUklkRkVzUE45enU3ZWw2eng2IiwiaXNzIjoiaHR0cHM6XC9cL3Nzby5tZXljbG91ZC5uZXQ6OTAzMSIsImlhdCI6MTM5MzczNzA3MSwiZXhwIjoxMzkzNzM3MzcxLCJub25jZSI6ImNiYTU2NjY2LTRiMTItNDU2YS04NDA3LTNkMzAyM2ZhMTAwMiIsImF0X2hhc2giOiJrdHFvZVBhc2praVY5b2Z0X3o5NnJBIn0.g1Jc9DohWFfFG3ppWfvW16ib6YBaONC5VMs8J61i5j5QLieY-mBEeVi1D3vr5IFWCfivY4hZcHtoJHgZk1qCumkAMDymsLGX-IGA7yFU8LOjUdR4IlCPlZxZ_vhqr_0gQ9pCFKDkiOv1LVv5x3YgAdhHhpZhxK6rWxojg2RddzvZ9Xi5u2V1UZ0jukwyG2d4PRzDn7WoRNDGwYOEt4qY7lv_NO2TY2eAklP-xYBWu0b9FBElapnstqbZgAXdndNs-Wqp4gyQG5D0owLzxPErR9MnpQfgNcai-PlWI_UrvoopKNbX0ai2zfkuQ-qh6Xn8zgkiaYDHzq4gzwRfwazaqA",
	}
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	userTokenString := jwtmanager.CreateUserTokenString(*user, customClaims, tokens)

	req, err := http.NewRequest("GET", "/validate", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{
		// Name:    cfg.Cfg.Cookie.Name + "_1of1",
		Name:    cfg.Cfg.Cookie.Name,
		Value:   userTokenString,
		Expires: time.Now().Add(1 * time.Hour),
	})

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(ValidateRequestHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	groupHeader := "X-Vouch-IdP-Claims-Groups"
	booleanHeader := "X-Vouch-IdP-Claims-Boolean-Claim"
	familyNameHeader := "X-Vouch-IdP-Claims-Family-Name"

	// Check that the custom claim headers are what we expected
	customClaimHeaders := map[string][]string{
		strings.ToLower(groupHeader):      []string{},
		strings.ToLower(booleanHeader):    []string{},
		strings.ToLower(familyNameHeader): []string{},
	}

	for k, v := range rr.Result().Header {
		k = strings.ToLower(k)
		if _, exist := customClaimHeaders[k]; exist {
			customClaimHeaders[k] = v
		}
	}
	expectedCustomClaimHeaders := map[string][]string{
		strings.ToLower(groupHeader):      []string{"\"Website Users\",\"Test Group\""},
		strings.ToLower(booleanHeader):    []string{"true"},
		strings.ToLower(familyNameHeader): []string{"Tester"},
	}
	assert.Equal(t, expectedCustomClaimHeaders, customClaimHeaders)
}

func TestVerifyUserPositiveUserInWhiteList(t *testing.T) {
	setUp("/config/testing/handler_whitelist.yml")
	user := &structs.User{Username: "test@example.com", Email: "test@example.com", Name: "Test Name"}
	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveAllowAllUsers(t *testing.T) {
	setUp("/config/testing/handler_allowallusers.yml")

	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}

	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByEmail(t *testing.T) {
	setUp("/config/testing/handler_email.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByTeam(t *testing.T) {
	setUp("/config/testing/handler_teams.yml")

	// cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team2", "org1/team1")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	user.TeamMemberships = append(user.TeamMemberships, "org1/team3")
	user.TeamMemberships = append(user.TeamMemberships, "org1/team1")
	ok, err := VerifyUser(*user)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegativeByTeam(t *testing.T) {
	setUp("/config/testing/handler_teams.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	// cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team1")

	ok, err := VerifyUser(*user)
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestVerifyUserPositiveNoDomainsConfigured(t *testing.T) {
	setUp("/config/testing/handler_nodomains.yml")

	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	cfg.Cfg.Domains = make([]string, 0)
	ok, err := VerifyUser(*user)

	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegative(t *testing.T) {
	setUp("/config/testing/test_config.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	ok, err := VerifyUser(*user)

	assert.False(t, ok)
	assert.NotNil(t, err)
}
