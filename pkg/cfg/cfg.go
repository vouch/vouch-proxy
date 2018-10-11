package cfg

import (
	"errors"
	"flag"
	"io/ioutil"
	"math/rand"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/spf13/viper"
)

// CfgT lasso jwt cookie configuration
type CfgT struct {
	LogLevel      string   `mapstructure:"logLevel"`
	Listen        string   `mapstructure:"listen"`
	Port          int      `mapstructure:"port"`
	Domains       []string `mapstructure:"domains"`
	AllowAllUsers bool     `mapstructure:"allowAllUsers"`
	PublicAccess  bool     `mapstructure:"publicAccess"`
	JWT           struct {
		MaxAge   int    `mapstructure:"maxAge"`
		Issuer   string `mapstructure:"issuer"`
		Secret   string `mapstructure:"secret"`
		Compress bool   `mapstructure:"compress"`
	}
	Cookie struct {
		Name     string `mapstructure:"name"`
		Domain   string `mapstructure:"domain"`
		Secure   bool   `mapstructure:"secure"`
		HTTPOnly bool   `mapstructure:"httpOnly"`
	}
	Headers struct {
		JWT         string `mapstructure:"jwt"`
		User        string `mapstructure:"user"`
		QueryString string `mapstructure:"querystring"`
		Redirect    string `mapstructure:"redirect"`
		Success     string `mapstructure:"success"`
	}
	DB struct {
		File string `mapstructure:"file"`
	}
	Session struct {
		Name string `mapstructure:"name"`
	}
	TestURL string `mapstructure:"test_url"`
	Testing bool   `mapstructure:"testing"`
	WebApp  bool   `mapstructure:"webapp"`
}

// oauth config items endoint for access
type oauthConfig struct {
	Provider        string   `mapstructure:"provider"`
	ClientID        string   `mapstructure:"client_id"`
	ClientSecret    string   `mapstructure:"client_secret"`
	AuthURL         string   `mapstructure:"auth_url"`
	TokenURL        string   `mapstructure:"token_url"`
	RedirectURL     string   `mapstructure:"callback_url"`
	RedirectURLs    []string `mapstructure:"callback_urls"`
	Scopes          []string `mapstructure:"scopes"`
	UserInfoURL     string   `mapstructure:"user_info_url"`
	PreferredDomain string   `mapstructre:"preferredDomain"`
}

// OAuthProviders holds the stings for
type OAuthProviders struct {
	Google    string
	GitHub    string
	IndieAuth string
	OIDC      string
}

var (
	// Cfg the main exported config variable
	Cfg CfgT

	// GenOAuth exported OAuth config variable
	// TODO: I think GenOAuth and OAuthConfig can be combined!
	// perhaps by https://golang.org/doc/effective_go.html#embedding
	GenOAuth *oauthConfig

	// OAuthClient is the configured client which will call the provider
	// this actually carries the oauth2 client ala oauthclient.Client(oauth2.NoContext, providerToken)
	OAuthClient *oauth2.Config
	// OAuthopts authentication options
	OAuthopts oauth2.AuthCodeOption

	// Providers static strings to test against
	Providers = &OAuthProviders{
		Google:    "google",
		GitHub:    "github",
		IndieAuth: "indieauth",
		OIDC:      "oidc",
	}
)

// RequiredOptions must have these fields set for minimum viable config
var RequiredOptions = []string{"oauth.provider", "oauth.client_id"}

func init() {
	// from config file
	ParseConfig()

	// can pass loglevel on the command line
	var ll = flag.String("loglevel", Cfg.LogLevel, "enable debug log output")
	flag.Parse()
	if *ll == "debug" {
		log.SetLevel(log.DebugLevel)
		log.Debug("logLevel set to debug")
	}

	setDefaults()
	log.Debug(viper.AllSettings())
}

// ParseConfig parse the config file
func ParseConfig() {
	log.Debug("opening config")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(os.Getenv("LASSO_ROOT") + "config")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatalf("Fatal error config file: %s", err.Error())
		panic(err)
	}
	UnmarshalKey("lasso", &Cfg)
	errT := BasicTest()
	if errT != nil {
		// log.Fatalf(err.prob)
		panic(errT)
	}
	log.Debugf("secret: %s", string(Cfg.JWT.Secret))
}

// UnmarshalKey populate struct from contents of cfg tree at key
func UnmarshalKey(key string, rawVal interface{}) error {
	return viper.UnmarshalKey(key, rawVal)
}

// Get string value for key
func Get(key string) string {
	return viper.GetString(key)
}

// BasicTest just a quick sanity check to see if the config is sound
func BasicTest() error {
	for _, opt := range RequiredOptions {
		if !viper.IsSet(opt) {
			return errors.New("configuration option " + opt + " is not set in config")
		}
	}
	return nil
}

// setDefaults set default options for some items
func setDefaults() {

	// this should really be done by Viper up in parseConfig but..
	// nested defaults is currently *broken*
	// https://github.com/spf13/viper/issues/309
	// viper.SetDefault("listen", "0.0.0.0")
	// viper.SetDefault(Cfg.Port, 9090)
	// viper.SetDefault("Headers.SSO", "X-Lasso-Token")
	// viper.SetDefault("Headers.Redirect", "X-Lasso-Requested-URI")
	// viper.SetDefault("Cookie.Name", "Lasso")

	// logging
	if !viper.IsSet("lasso.logLevel") {
		Cfg.LogLevel = "info"
	}
	// network defaults
	if !viper.IsSet("lasso.listen") {
		Cfg.Listen = "0.0.0.0"
	}
	if !viper.IsSet("lasso.port") {
		Cfg.Port = 9090
	}
	if !viper.IsSet("lasso.allowAllUsers") {
		Cfg.AllowAllUsers = false
	}
	if !viper.IsSet("lasso.publicAccess") {
		Cfg.PublicAccess = false
	}

	// jwt defaults
	if !viper.IsSet("lasso.jwt.secret") {
		Cfg.JWT.Secret = getOrGenerateJWTSecret()
	}
	if !viper.IsSet("lasso.jwt.issuer") {
		Cfg.JWT.Issuer = "Lasso"
	}
	if !viper.IsSet("lasso.jwt.maxAge") {
		Cfg.JWT.MaxAge = 240
	}
	if !viper.IsSet("lasso.jwt.compress") {
		Cfg.JWT.Compress = true
	}

	// cookie defaults
	if !viper.IsSet("lasso.cookie.name") {
		Cfg.Cookie.Name = "LassoCookie"
	}
	if !viper.IsSet("lasso.cookie.secure") {
		Cfg.Cookie.Secure = false
	}
	if !viper.IsSet("lasso.cookie.httpOnly") {
		Cfg.Cookie.HTTPOnly = true
	}

	// headers defaults
	if !viper.IsSet("lasso.headers.jwt") {
		Cfg.Headers.JWT = "X-Lasso-Token"
	}
	if !viper.IsSet("lasso.headers.querystring") {
		Cfg.Headers.QueryString = "access_token"
	}
	if !viper.IsSet("lasso.headers.redirect") {
		Cfg.Headers.Redirect = "X-Lasso-Requested-URI"
	}
	if !viper.IsSet("lasso.headers.user") {
		Cfg.Headers.User = "X-Lasso-User"
	}
	if !viper.IsSet("lasso.headers.success") {
		Cfg.Headers.Success = "X-Lasso-Success"
	}

	// db defaults
	if !viper.IsSet("lasso.db.file") {
		Cfg.DB.File = "data/lasso_bolt.db"
	}

	// session HERE
	if !viper.IsSet("lasso.session.name") {
		Cfg.Session.Name = "lassoSession"
	}

	// testing convenience variable
	if !viper.IsSet("lasso.testing") {
		Cfg.Testing = false
	}
	if !viper.IsSet("lasso.test_url") {
		Cfg.TestURL = ""
	}
	// TODO: proably change this name, maybe set the domain/port the webapp runs on
	if !viper.IsSet("lasso.webapp") {
		Cfg.WebApp = false
	}

	// OAuth defaults and client configuration
	err := UnmarshalKey("oauth", &GenOAuth)
	if err == nil {
		if GenOAuth.Provider == Providers.Google {
			setDefaultsGoogle()
			// setDefaultsGoogle also configures the OAuthClient
		} else if GenOAuth.Provider == Providers.GitHub {
			setDefaultsGitHub()
			configureOAuthClient()
		} else {
			configureOAuthClient()
		}
	}
}

func setDefaultsGoogle() {
	log.Info("configuring Google OAuth")
	GenOAuth.UserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	OAuthClient = &oauth2.Config{
		ClientID:     GenOAuth.ClientID,
		ClientSecret: GenOAuth.ClientSecret,
		Scopes: []string{
			// You have to select a scope from
			// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	log.Infof("setting Google OAuth preferred login domain param 'hd' to %s", GenOAuth.PreferredDomain)
	OAuthopts = oauth2.SetAuthURLParam("hd", GenOAuth.PreferredDomain)
}

func setDefaultsGitHub() {
	// log.Info("configuring GitHub OAuth")
	if GenOAuth.AuthURL == "" {
		GenOAuth.AuthURL = github.Endpoint.AuthURL
	}
	if GenOAuth.TokenURL == "" {
		GenOAuth.TokenURL = github.Endpoint.TokenURL
	}
	if GenOAuth.UserInfoURL == "" {
		GenOAuth.UserInfoURL = "https://api.github.com/user?access_token="
	}
	if len(GenOAuth.Scopes) == 0 {
		GenOAuth.Scopes = []string{"user"}
	}
}

func configureOAuthClient() {
	log.Infof("configuring %s OAuth with Endpoint %s", GenOAuth.Provider, GenOAuth.AuthURL)
	OAuthClient = &oauth2.Config{
		ClientID:     GenOAuth.ClientID,
		ClientSecret: GenOAuth.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  GenOAuth.AuthURL,
			TokenURL: GenOAuth.TokenURL,
		},
		RedirectURL: GenOAuth.RedirectURL,
		Scopes:      GenOAuth.Scopes,
	}
}

var secretFile = os.Getenv("LASSO_ROOT") + "config/secret"

// a-z A-Z 0-9 except no l, o, O
const charRunes = "abcdefghijkmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ012346789"

const secretLen = 18

func getOrGenerateJWTSecret() string {
	b, err := ioutil.ReadFile(secretFile)
	if err == nil {
		log.Info("jwt.secret read from " + secretFile)
	} else {
		// then generate a new secret and store it in the file
		log.Debug(err)
		log.Info("jwt.secret not found in " + secretFile)
		log.Warn("generating new jwt.secret and storing it in " + secretFile)

		rand.Seed(time.Now().UnixNano())
		b := make([]byte, secretLen)
		for i := range b {
			b[i] = charRunes[rand.Intn(len(charRunes))]
		}
		err := ioutil.WriteFile(secretFile, b, 0600)
		if err != nil {
			log.Debug(err)
		}
	}
	return string(b)
}
