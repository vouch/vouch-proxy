module github.com/vouch/vouch-proxy

go 1.16

require (
	cloud.google.com/go/compute v1.15.1 // indirect
	github.com/bmizerany/perks v0.0.0-20141205001514-d9a9656a3a4b // indirect
	github.com/dgryski/go-gk v0.0.0-20200319235926-a69029f61654 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/google/go-cmp v0.5.9
	github.com/gorilla/sessions v1.2.1
	github.com/influxdata/tdigest v0.0.1 // indirect
	github.com/julienschmidt/httprouter v1.3.0
	github.com/karupanerura/go-mock-http-response v0.0.0-20171201120521-7c242a447d45
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0
	github.com/nirasan/go-oauth-pkce-code-verifier v0.0.0-20220510032225-4f9f17eaec4c
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/spf13/viper v1.15.0
	github.com/streadway/quantile v0.0.0-20150917103942-b0c588724d25 // indirect
	github.com/stretchr/testify v1.8.1
	github.com/theckman/go-securerandom v0.1.1
	github.com/tsenart/vegeta v12.7.0+incompatible
	go.uber.org/multierr v1.9.0 // indirect
	go.uber.org/zap v1.24.0
	golang.org/x/net v0.5.0
	golang.org/x/oauth2 v0.4.0
)

replace go.uber.org/atomic => go.uber.org/atomic v1.9.0
