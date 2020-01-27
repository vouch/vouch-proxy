package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/model"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

var testdb = "/tmp/handlers-test.db"

func init() {
	cfg.RootDir = "../"
	cfg.InitForTestPurposesWithPath("../config/test_config.yml")
	Init()

	model.Db, _ = model.OpenDB(testdb)
}

func TestValidateRequestHandlerWithGroupClaims(t *testing.T) {

	user := structs.User{
		Username: "test@testing.com",
		Name: "Test Name",
	}

	customClaims := structs.CustomClaims{
		Claims: map[string]interface{} {
			"sub": "f:a95afe53-60ba-4ac6-af15-fab870e72f3d:mrtester",
			"groups": []string{
				"Website Users",
				"Test Group",
			},
			"given_name": "Mister",
			"family_name": "Tester",
			"email": "mrtester@test.int",
			"boolean_claim": true,
		},
	}

	tokens := structs.PTokens{
		PAccessToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRvaXU4In0.eyJzdWIiOiJuZnlmZSIsImF1ZCI6ImltX29pY19jbGllbnQiLCJqdGkiOiJUOU4xUklkRkVzUE45enU3ZWw2eng2IiwiaXNzIjoiaHR0cHM6XC9cL3Nzby5tZXljbG91ZC5uZXQ6OTAzMSIsImlhdCI6MTM5MzczNzA3MSwiZXhwIjoxMzkzNzM3MzcxLCJub25jZSI6ImNiYTU2NjY2LTRiMTItNDU2YS04NDA3LTNkMzAyM2ZhMTAwMiIsImF0X2hhc2giOiJrdHFvZVBhc2praVY5b2Z0X3o5NnJBIn0.g1Jc9DohWFfFG3ppWfvW16ib6YBaONC5VMs8J61i5j5QLieY-mBEeVi1D3vr5IFWCfivY4hZcHtoJHgZk1qCumkAMDymsLGX-IGA7yFU8LOjUdR4IlCPlZxZ_vhqr_0gQ9pCFKDkiOv1LVv5x3YgAdhHhpZhxK6rWxojg2RddzvZ9Xi5u2V1UZ0jukwyG2d4PRzDn7WoRNDGwYOEt4qY7lv_NO2TY2eAklP-xYBWu0b9FBElapnstqbZgAXdndNs-Wqp4gyQG5D0owLzxPErR9MnpQfgNcai-PlWI_UrvoopKNbX0ai2zfkuQ-qh6Xn8zgkiaYDHzq4gzwRfwazaqA",
		PIdToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRvaXU4In0.eyJzdWIiOiJuZnlmZSIsImF1ZCI6ImltX29pY19jbGllbnQiLCJqdGkiOiJUOU4xUklkRkVzUE45enU3ZWw2eng2IiwiaXNzIjoiaHR0cHM6XC9cL3Nzby5tZXljbG91ZC5uZXQ6OTAzMSIsImlhdCI6MTM5MzczNzA3MSwiZXhwIjoxMzkzNzM3MzcxLCJub25jZSI6ImNiYTU2NjY2LTRiMTItNDU2YS04NDA3LTNkMzAyM2ZhMTAwMiIsImF0X2hhc2giOiJrdHFvZVBhc2praVY5b2Z0X3o5NnJBIn0.g1Jc9DohWFfFG3ppWfvW16ib6YBaONC5VMs8J61i5j5QLieY-mBEeVi1D3vr5IFWCfivY4hZcHtoJHgZk1qCumkAMDymsLGX-IGA7yFU8LOjUdR4IlCPlZxZ_vhqr_0gQ9pCFKDkiOv1LVv5x3YgAdhHhpZhxK6rWxojg2RddzvZ9Xi5u2V1UZ0jukwyG2d4PRzDn7WoRNDGwYOEt4qY7lv_NO2TY2eAklP-xYBWu0b9FBElapnstqbZgAXdndNs-Wqp4gyQG5D0owLzxPErR9MnpQfgNcai-PlWI_UrvoopKNbX0ai2zfkuQ-qh6Xn8zgkiaYDHzq4gzwRfwazaqA",
	}

	userTokenString := jwtmanager.CreateUserTokenString(user, customClaims, tokens)

	req, err := http.NewRequest("GET", "/validate", nil);
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(&http.Cookie{
		Name: cfg.Cfg.Cookie.Name + "_1of1",
		Value: userTokenString,
		Expires: time.Now().Add(1 * time.Hour),
	})
	
	rr := httptest.NewRecorder()
	cfg.Cfg.AllowAllUsers = true
	cfg.Cfg.Headers.Claims = []string{"groups", "boolean_claim"}
	handler := http.HandlerFunc(ValidateRequestHandler)

	handler.ServeHTTP(rr, req)
	
	if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v",
            status, http.StatusOK)
    }

	// Check that the custom claim headers are what we expected
	customClaimHeaders := map[string][]string{
		strings.ToLower(cfg.Cfg.Headers.ClaimHeader + "groups") : []string{},
		strings.ToLower(cfg.Cfg.Headers.ClaimHeader + "boolean_claim") : []string{},
	}

	for k, v := range rr.Result().Header {
		k = strings.ToLower(k)
		if _, exist := customClaimHeaders[k]; exist {
			customClaimHeaders[k] = v
		}
	}
	expectedCustomClaimHeaders := map[string][]string{
		strings.ToLower(cfg.Cfg.Headers.ClaimHeader + "groups") : []string{"\"Website Users\",\"Test Group\""},
		strings.ToLower(cfg.Cfg.Headers.ClaimHeader + "boolean_claim") : []string{"true"},
	}
	assert.Equal(t, expectedCustomClaimHeaders, customClaimHeaders)
}