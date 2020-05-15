/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	vegeta "github.com/tsenart/vegeta/lib"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

func BenchmarkValidateRequestHandler(b *testing.B) {
	setUp("/config/testing/handler_email.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	tokens := structs.PTokens{}
	customClaims := structs.CustomClaims{}

	userTokenString := jwtmanager.CreateUserTokenString(*user, customClaims, tokens)

	c := &http.Cookie{
		// Name:    cfg.Cfg.Cookie.Name + "_1of1",
		Name:    cfg.Cfg.Cookie.Name,
		Value:   userTokenString,
		Expires: time.Now().Add(1 * time.Hour),
	}

	handler := jwtmanager.JWTCacheHandler(http.HandlerFunc(ValidateRequestHandler))
	// handler := http.HandlerFunc(ValidateRequestHandler)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, err := http.NewRequest("GET", "/validate", nil)
	if err != nil {
		b.Fatal(err)
	}
	req.Host = "myapp.example.com"
	req.AddCookie(c)
	w := httptest.NewRecorder()

	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, req)
	}

}

func TestValidateRequestHandlerPerf(t *testing.T) {
	if _, ok := os.LookupEnv("ISTRAVIS"); ok {
		t.Skip("travis doesn't like perf tests, skipping")
	}

	setUp("/config/testing/handler_email.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	tokens := structs.PTokens{}
	customClaims := structs.CustomClaims{}

	userTokenString := jwtmanager.CreateUserTokenString(*user, customClaims, tokens)

	c := &http.Cookie{
		// Name:    cfg.Cfg.Cookie.Name + "_1of1",
		Name:    cfg.Cfg.Cookie.Name,
		Value:   userTokenString,
		Expires: time.Now().Add(1 * time.Hour),
	}

	// handler := http.HandlerFunc(ValidateRequestHandler)
	handler := jwtmanager.JWTCacheHandler(http.HandlerFunc(ValidateRequestHandler))
	ts := httptest.NewServer(handler)
	defer ts.Close()

	freq := 1000
	duration := 5 * time.Second

	rate := vegeta.Rate{Freq: freq, Per: time.Second}
	h := &http.Header{}
	h.Add("Cookie", c.String())
	h.Add("Host", "myapp.example.com")
	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: "GET",
		URL:    ts.URL,
		Header: *h,
	})

	attacker := vegeta.NewAttacker()

	var metrics vegeta.Metrics
	mustFail := false
	for res := range attacker.Attack(targeter, rate, duration, "Big Bang!") {
		if res.Code != http.StatusOK {
			t.Logf("/validate perf %d response code %d", res.Seq, res.Code)
			mustFail = true
		}
		metrics.Add(res)
	}
	metrics.Close()

	limit := time.Millisecond
	if mustFail || metrics.Latencies.P95 > limit {
		t.Logf("99th percentile latencies: %s", metrics.Latencies.P99)
		t.Logf("95th percentile latencies: %s", metrics.Latencies.P95)
		t.Logf("50th percentile latencies: %s", metrics.Latencies.P50)
		t.Logf("min latencies: %s", metrics.Latencies.Min)
		t.Logf("max latencies: %s", metrics.Latencies.Max)
		t.Logf("/validate 95th percentile latency is higher than %s", limit)
		if mustFail {
			t.Logf("not all requests were %d", http.StatusOK)
		}
		t.FailNow()
	}

}

func TestValidateRequestHandlerWithGroupClaims(t *testing.T) {
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
			// Auth0 custom claim are URLs
			// https://auth0.com/docs/tokens/guides/create-namespaced-custom-claims
			"http://www.example.com/favorite_color": "blue",
		},
	}

	groupHeader := "X-Vouch-IdP-Claims-Groups"
	booleanHeader := "X-Vouch-IdP-Claims-Boolean-Claim"
	familyNameHeader := "X-Vouch-IdP-Claims-Family-Name"
	favoriteColorHeader := "X-Vouch-IdP-Claims-Www-Example-Com-Favorite-Color"

	tokens := structs.PTokens{}

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

	// Check that the custom claim headers are what we expected
	customClaimHeaders := map[string][]string{
		strings.ToLower(groupHeader):         {},
		strings.ToLower(booleanHeader):       {},
		strings.ToLower(familyNameHeader):    {},
		strings.ToLower(favoriteColorHeader): {},
	}

	for k, v := range rr.Result().Header {
		k = strings.ToLower(k)
		if _, exist := customClaimHeaders[k]; exist {
			customClaimHeaders[k] = v
		}
	}
	expectedCustomClaimHeaders := map[string][]string{
		strings.ToLower(groupHeader):         {"\"Website Users\",\"Test Group\""},
		strings.ToLower(booleanHeader):       {"true"},
		strings.ToLower(familyNameHeader):    {"Tester"},
		strings.ToLower(favoriteColorHeader): {"blue"},
	}
	assert.Equal(t, expectedCustomClaimHeaders, customClaimHeaders)
}

func TestJWTCacheHandler(t *testing.T) {
	setUp("/config/testing/handler_logout_url.yml")
	handler := jwtmanager.JWTCacheHandler(http.HandlerFunc(ValidateRequestHandler))

	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	tokens := structs.PTokens{}
	customClaims := structs.CustomClaims{}

	userTokenString := jwtmanager.CreateUserTokenString(*user, customClaims, tokens)

	c := &http.Cookie{
		// Name:    cfg.Cfg.Cookie.Name + "_1of1",
		Name:    cfg.Cfg.Cookie.Name,
		Value:   userTokenString,
		Expires: time.Now().Add(1 * time.Hour),
		Domain:  cfg.Cfg.Cookie.Domain,
	}

	cBlank := &http.Cookie{
		// Name:    cfg.Cfg.Cookie.Name + "_1of1",
		Name:    cfg.Cfg.Cookie.Name,
		Value:   "",
		Expires: time.Now().Add(1 * time.Hour),
		Domain:  cfg.Cfg.Cookie.Domain,
	}

	tests := []struct {
		name     string
		cookie   *http.Cookie
		wantcode int
	}{
		{"authorized", c, http.StatusOK},
		{"authorized", c, http.StatusOK}, // because we're testing the cacheing we run these multiple times
		{"notauthorized", cBlank, http.StatusUnauthorized},
		{"notauthorized", cBlank, http.StatusUnauthorized},
		{"authorized", c, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/validate", nil)
			req.Host = "myapp.example.com"
			req.AddCookie(tt.cookie)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.wantcode {
				t.Errorf("JWTCacheHandler() = %v, want %v", rr.Code, tt.wantcode)
			}
		})
	}
}
