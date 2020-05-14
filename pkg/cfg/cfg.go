/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"regexp"

	"github.com/mitchellh/mapstructure"

	"golang.org/x/oauth2"

	"github.com/spf13/viper"
	securerandom "github.com/theckman/go-securerandom"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config vouch jwt cookie configuration
type Config struct {
	LogLevel      string   `mapstructure:"logLevel"`
	Listen        string   `mapstructure:"listen"`
	Port          int      `mapstructure:"port"`
	Domains       []string `mapstructure:"domains"`
	WhiteList     []string `mapstructure:"whitelist"`
	RegexWhiteList []string `mapstructure:"regexWhiteList"`
	TeamWhiteList []string `mapstructure:"teamWhitelist"`
	AllowAllUsers bool     `mapstructure:"allowAllUsers"`
	PublicAccess  bool     `mapstructure:"publicAccess"`
	JWT           struct {
		MaxAge   int    `mapstructure:"maxAge"` // in minutes
		Issuer   string `mapstructure:"issuer"`
		Secret   string `mapstructure:"secret"`
		Compress bool   `mapstructure:"compress"`
	}
	Cookie struct {
		Name     string `mapstructure:"name"`
		Domain   string `mapstructure:"domain"`
		Secure   bool   `mapstructure:"secure"`
		HTTPOnly bool   `mapstructure:"httpOnly"`
		MaxAge   int    `mapstructure:"maxage"`
		SameSite string `mapstructure:"sameSite"`
	}

	Headers struct {
		JWT           string            `mapstructure:"jwt"`
		User          string            `mapstructure:"user"`
		QueryString   string            `mapstructure:"querystring"`
		Redirect      string            `mapstructure:"redirect"`
		Success       string            `mapstructure:"success"`
		ClaimHeader   string            `mapstructure:"claimheader"`
		Claims        []string          `mapstructure:"claims"`
		AccessToken   string            `mapstructure:"accesstoken"`
		IDToken       string            `mapstructure:"idtoken"`
		ClaimsCleaned map[string]string // the rawClaim is mapped to the actual claims header
	}
	Session struct {
		Name string `mapstructure:"name"`
		Key  string `mapstructure:"key"`
	}
	TestURL            string   `mapstructure:"test_url"`
	TestURLs           []string `mapstructure:"test_urls"`
	Testing            bool     `mapstructure:"testing"`
	LogoutRedirectURLs []string `mapstructure:"post_logout_redirect_uris"`
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
	UserTeamURL     string   `mapstructure:"user_team_url"`
	UserOrgURL      string   `mapstructure:"user_org_url"`
	PreferredDomain string   `mapstructre:"preferredDomain"`
}

// OAuthProviders holds the stings for
type OAuthProviders struct {
	Google        string
	GitHub        string
	IndieAuth     string
	ADFS          string
	OIDC          string
	HomeAssistant string
	OpenStax      string
	Nextcloud     string
}

type branding struct {
	LCName    string // lower case
	UCName    string // upper case
	CcName    string // camel case
	FullName  string // Vouch Proxy
	OldLCName string // lasso
	URL       string // https://github.com/vouch/vouch-proxy
}

var (
	// Branding that's our name
	Branding = branding{"vouch", "VOUCH", "Vouch", "Vouch Proxy", "lasso", "https://github.com/vouch/vouch-proxy"}

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
		Google:        "google",
		GitHub:        "github",
		IndieAuth:     "indieauth",
		ADFS:          "adfs",
		OIDC:          "oidc",
		HomeAssistant: "homeassistant",
		OpenStax:      "openstax",
		Nextcloud:     "nextcloud",
	}

	// RequiredOptions must have these fields set for minimum viable config
	RequiredOptions = []string{"oauth.provider", "oauth.client_id"}

	// RootDir is where Vouch Proxy looks for ./config/config.yml, ./data, ./static and ./templates
	RootDir string

	secretFile string

	// CmdLine command line arguments
	CmdLine = &cmdLineFlags{
		IsHealthCheck: flag.Bool("healthcheck", false, "invoke healthcheck (check process return value)"),
		port:          flag.Int("port", -1, "port"),
		configFile:    flag.String("config", "", "specify alternate config.yml file as command line arg"),
		// https://github.com/uber-go/zap/blob/master/flag.go
		logLevel: zap.LevelFlag("loglevel", cmdLineLoggingDefault, "set log level to one of: panic, error, warn, info, debug"),
		logTest:  flag.Bool("logtest", false, "print a series of log messages and exit (used for testing)"),
	}

	// Cfg the main exported config variable
	Cfg = &Config{}
	// IsHealthCheck see main.go
	IsHealthCheck = false
	// CompiledRegexWhiteList see auth.go
	CompiledRegexWhiteList []*regexp.Regexp
)

type cmdLineFlags struct {
	IsHealthCheck *bool
	port          *int
	configFile    *string
	logLevel      *zapcore.Level
	logTest       *bool
}

const (
	// for a Base64 string we need 44 characters to get 32bytes (6 bits per char)
	minBase64Length = 44
	base64Bytes     = 32
)

// Configure called at the very top of main()
func Configure() {

	Logging.configureFromCmdline()

	setRootDir()
	secretFile = filepath.Join(RootDir, "config/secret")

	// bail if we're testing
	if flag.Lookup("test.v") != nil {
		log.Debug("`go test` detected, not loading regular config")
		Logging.setLogLevel(zap.WarnLevel)
		return
	}

	parseConfig()
	Logging.configure()
	setDefaults()
	cleanClaimsHeaders()
	if *CmdLine.port != -1 {
		Cfg.Port = *CmdLine.port
	}

}

// ValidateConfiguration confirm the Configuration is valid
func ValidateConfiguration() {
	if Cfg.Testing {
		// Logging.setLogLevel(zap.DebugLevel)
		Logging.setDevelopmentLogger()
	}

	errT := basicTest()
	if errT != nil {
		log.Panic(errT)
	}

	log.Debugf("viper settings %+v", viper.AllSettings())
}

func setRootDir() {
	// set RootDir from VOUCH_ROOT env var, or to the executable's directory
	if os.Getenv(Branding.UCName+"_ROOT") != "" {
		RootDir = os.Getenv(Branding.UCName + "_ROOT")
		log.Warnf("set cfg.RootDir from VOUCH_ROOT env var: %s", RootDir)
	} else {
		ex, errEx := os.Executable()
		if errEx != nil {
			log.Panic(errEx)
		}
		RootDir = filepath.Dir(ex)
		log.Debugf("cfg.RootDir: %s", RootDir)
	}
}

// InitForTestPurposes is called by most *_testing.go files in Vouch Proxy
func InitForTestPurposes() {
	InitForTestPurposesWithProvider("")
}

// InitForTestPurposesWithProvider just for testing
func InitForTestPurposesWithProvider(provider string) {
	Cfg = &Config{} // clear it out since we're called multiple times from subsequent tests
	Logging.setLogLevel(zapcore.WarnLevel)
	setRootDir()
	// _, b, _, _ := runtime.Caller(0)
	// basepath := filepath.Dir(b)
	configEnv := os.Getenv(Branding.UCName + "_CONFIG")
	if configEnv == "" {
		if err := os.Setenv(Branding.UCName+"_CONFIG", filepath.Join(RootDir, "config/testing/test_config.yml")); err != nil {
			log.Error(err)
		}
	}
	// Configure()
	// setRootDir()
	parseConfig()
	setDefaults()
	// setDevelopmentLogger()

	// Needed to override the provider, which is otherwise set via yml
	if provider != "" {
		GenOAuth.Provider = provider
		setProviderDefaults()
	}
	cleanClaimsHeaders()

}

// parseConfig parse the config file
func parseConfig() {
	configEnv := os.Getenv(Branding.UCName + "_CONFIG")

	if configEnv != "" {
		log.Warnf("config file loaded from environmental variable %s: %s", Branding.UCName+"_CONFIG", configEnv)
		configFile, _ := filepath.Abs(configEnv)
		viper.SetConfigFile(configFile)
	} else if *CmdLine.configFile != "" {
		log.Infof("config file set on commandline: %s", *CmdLine.configFile)
		viper.AddConfigPath("/")
		viper.AddConfigPath(RootDir)
		viper.AddConfigPath(filepath.Join(RootDir, "config"))
		viper.SetConfigFile(*CmdLine.configFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(filepath.Join(RootDir, "config"))
	}
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatalf("Fatal error config file: %s", err.Error())
		log.Panic(err)
	}

	if err = checkConfigFileWellFormed(); err != nil {
		log.Error("configuration error: config file should have only two top level elements: `vouch` and `oauth`.  These and other syntax errors follow...")
		log.Error(err)
		log.Error("continuing... (maybe you know what you're doing :)")
	}

	if err = UnmarshalKey(Branding.LCName, &Cfg); err != nil {
		log.Error(err)
	}

	if len(Cfg.Domains) == 0 {
		// then lets check for "lasso"
		var oldConfig = &Config{}
		if err = UnmarshalKey(Branding.OldLCName, &oldConfig); err != nil {
			log.Error(err)
		}

		if len(oldConfig.Domains) != 0 {
			log.Errorf(`

IMPORTANT!

please update your config file to change '%s:' to '%s:' as per %s
			`, Branding.OldLCName, Branding.LCName, Branding.URL)
			Cfg = oldConfig
		}
	}

	// don't log the secret!
	// log.Debugf("secret: %s", string(Cfg.JWT.Secret))
}

// use viper and mapstructure check to see if
// https://pkg.go.dev/github.com/spf13/viper@v1.6.3?tab=doc#Unmarshal
// https://pkg.go.dev/github.com/mitchellh/mapstructure?tab=doc#DecoderConfig
func checkConfigFileWellFormed() error {
	opt := func(dc *mapstructure.DecoderConfig) {
		dc.ErrorUnused = true
	}

	type quick struct {
		Vouch Config
		OAuth oauthConfig
	}
	q := &quick{}

	return viper.Unmarshal(q, opt)
}

// UnmarshalKey populate struct from contents of cfg tree at key
func UnmarshalKey(key string, rawVal interface{}) error {
	return viper.UnmarshalKey(key, rawVal)
}

// Get string value for key
func Get(key string) string {
	return viper.GetString(key)
}

// basicTest just a quick sanity check to see if the config is sound
func basicTest() error {

	// check oauth config
	if err := oauthBasicTest(); err != nil {
		return err
	}

	for _, opt := range RequiredOptions {
		if !viper.IsSet(opt) {
			return errors.New("configuration error: required configuration option " + opt + " is not set")
		}
	}
	// Domains is required _unless_ Cfg.AllowAllUsers is set
	if !viper.IsSet(Branding.LCName+".allowAllUsers") && !viper.IsSet(Branding.LCName+".domains") {
		return fmt.Errorf("configuration error: either one of %s or %s needs to be set (but not both)", Branding.LCName+".domains", Branding.LCName+".allowAllUsers")
	}

	// issue a warning if the secret is too small
	log.Debugf("vouch.jwt.secret is %d characters long", len(Cfg.JWT.Secret))
	if len(Cfg.JWT.Secret) < minBase64Length {
		log.Errorf("Your secret is too short! (%d characters long). Please consider deleting %s to automatically generate a secret of %d characters",
			len(Cfg.JWT.Secret),
			Branding.LCName+".jwt.secret",
			minBase64Length)
	}

	log.Debugf("vouch.session.key is %d characters long", len(Cfg.Session.Key))
	if len(Cfg.Session.Key) < minBase64Length {
		log.Errorf("Your session key is too short! (%d characters long). Please consider deleting %s to automatically generate a secret of %d characters",
			len(Cfg.Session.Key),
			Branding.LCName+".session.key",
			minBase64Length)
	}
	if Cfg.Cookie.MaxAge < 0 {
		return fmt.Errorf("configuration error: cookie maxAge cannot be lower than 0 (currently: %d)", Cfg.Cookie.MaxAge)
	}
	if Cfg.JWT.MaxAge <= 0 {
		return fmt.Errorf("configuration error: JWT maxAge cannot be zero or lower (currently: %d)", Cfg.JWT.MaxAge)
	}
	if Cfg.Cookie.MaxAge > Cfg.JWT.MaxAge {
		return fmt.Errorf("configuration error: Cookie maxAge (%d) cannot be larger than the JWT maxAge (%d)", Cfg.Cookie.MaxAge, Cfg.JWT.MaxAge)
	}
	// if using regexWhiteList, compile regex statements, and store them in cfg.CompiledRegexWhiteList
	if len(Cfg.RegexWhiteList) != 0 {
		for i, wl := range Cfg.RegexWhiteList {
			//generate regex array
			reWhiteList, reWhiteListErr := regexp.Compile(wl)
			if reWhiteListErr != nil {
				log.Fatalf("Uncompilable regex parameter: '%v'", wl)
			}
			CompiledRegexWhiteList = append(CompiledRegexWhiteList, reWhiteList)
			log.Debugf("Compiled regex parameter '%v'", CompiledRegexWhiteList[i])
		}
		log.Debugf("compiled regex array %v", CompiledRegexWhiteList)
	}
	return nil
}

// setDefaults set default options for most items
func setDefaults() {

	// this should really be done by Viper up in parseConfig but..
	// nested defaults is currently *broken*
	// https://github.com/spf13/viper/issues/309
	// viper.SetDefault("listen", "0.0.0.0")
	// viper.SetDefault(Cfg.Port, 9090)
	// viper.SetDefault("Headers.SSO", "X-"+Branding.CcName+"-Token")
	// viper.SetDefault("Headers.Redirect", "X-"+Branding.CcName+"-Requested-URI")
	// viper.SetDefault("Cookie.Name", "Vouch")

	// network defaults
	if !viper.IsSet(Branding.LCName + ".listen") {
		Cfg.Listen = "0.0.0.0"
	}

	if !viper.IsSet(Branding.LCName + ".port") {
		Cfg.Port = 9090
	}

	// bare minimum for healthcheck acheived
	if *CmdLine.IsHealthCheck {
		return
	}

	if !viper.IsSet(Branding.LCName + ".allowAllUsers") {
		Cfg.AllowAllUsers = false
	}
	if !viper.IsSet(Branding.LCName + ".publicAccess") {
		Cfg.PublicAccess = false
	}

	// jwt defaults
	if !viper.IsSet(Branding.LCName + ".jwt.secret") {
		Cfg.JWT.Secret = getOrGenerateJWTSecret()
	}
	if !viper.IsSet(Branding.LCName + ".jwt.issuer") {
		Cfg.JWT.Issuer = Branding.CcName
	}
	if !viper.IsSet(Branding.LCName + ".jwt.maxAge") {
		Cfg.JWT.MaxAge = 240
	}
	if !viper.IsSet(Branding.LCName + ".jwt.compress") {
		Cfg.JWT.Compress = true
	}

	// cookie defaults
	if !viper.IsSet(Branding.LCName + ".cookie.name") {
		Cfg.Cookie.Name = Branding.CcName + "Cookie"
	}
	if !viper.IsSet(Branding.LCName + ".cookie.secure") {
		Cfg.Cookie.Secure = false
	}
	if !viper.IsSet(Branding.LCName + ".cookie.httpOnly") {
		Cfg.Cookie.HTTPOnly = true
	}
	if !viper.IsSet(Branding.LCName + ".cookie.maxAge") {
		Cfg.Cookie.MaxAge = Cfg.JWT.MaxAge
	} else {
		// it is set!  is it bigger than jwt.maxage?
		if Cfg.Cookie.MaxAge > Cfg.JWT.MaxAge {
			log.Warnf("setting `%s.cookie.maxage` to `%s.jwt.maxage` value of %d minutes (curently set to %d minutes)", Branding.LCName, Branding.LCName, Cfg.JWT.MaxAge, Cfg.Cookie.MaxAge)
			Cfg.Cookie.MaxAge = Cfg.JWT.MaxAge
		}
	}

	// headers defaults
	if !viper.IsSet(Branding.LCName + ".headers.jwt") {
		Cfg.Headers.JWT = "X-" + Branding.CcName + "-Token"
	}
	if !viper.IsSet(Branding.LCName + ".headers.querystring") {
		Cfg.Headers.QueryString = "access_token"
	}
	if !viper.IsSet(Branding.LCName + ".headers.redirect") {
		Cfg.Headers.Redirect = "X-" + Branding.CcName + "-Requested-URI"
	}
	if !viper.IsSet(Branding.LCName + ".headers.user") {
		Cfg.Headers.User = "X-" + Branding.CcName + "-User"
	}
	if !viper.IsSet(Branding.LCName + ".headers.success") {
		Cfg.Headers.Success = "X-" + Branding.CcName + "-Success"
	}
	if !viper.IsSet(Branding.LCName + ".headers.claimheader") {
		Cfg.Headers.ClaimHeader = "X-" + Branding.CcName + "-IdP-Claims-"
	}

	// session
	if !viper.IsSet(Branding.LCName + ".session.name") {
		Cfg.Session.Name = Branding.CcName + "Session"
	}
	if !viper.IsSet(Branding.LCName + ".session.key") {
		log.Warn("generating random session.key")
		rstr, err := securerandom.Base64OfBytes(base64Bytes)
		if err != nil {
			log.Fatal(err)
		}
		Cfg.Session.Key = rstr
	}

	// testing convenience variable
	if !viper.IsSet(Branding.LCName + ".testing") {
		Cfg.Testing = false
	}
	if viper.IsSet(Branding.LCName + ".test_url") {
		Cfg.TestURLs = append(Cfg.TestURLs, Cfg.TestURL)
	}

	// OAuth defaults and client configuration
	err := UnmarshalKey("oauth", &GenOAuth)
	if err == nil {
		setProviderDefaults()
	}
}

func claimToHeader(claim string) (string, error) {
	was := claim

	// Auth0 allows "namespaceing" of claims and represents them as URLs
	claim = strings.TrimPrefix(claim, "http://")
	claim = strings.TrimPrefix(claim, "https://")

	// not allowed in header: "(),/:;<=>?@[\]{}"
	// https://greenbytes.de/tech/webdav/rfc7230.html#rfc.section.3.2.6
	// and we don't allow underscores `_` or periods `.` because nginx doesn't like them
	// "Valid names are composed of English letters, digits, hyphens, and possibly underscores"
	// as per http://nginx.org/en/docs/http/ngx_http_core_module.html#underscores_in_headers
	for _, r := range `"(),/\:;<=>?@[]{}_.` {
		claim = strings.ReplaceAll(claim, string(r), "-")
	}

	// The field-name must be composed of printable ASCII characters (i.e., characters)
	// that have values between 33. and 126., decimal, except colon).
	// https://github.com/vouch/vouch-proxy/issues/183#issuecomment-564427548
	// get the rune (char) for each claim character
	for _, r := range claim {
		// log.Debugf("claimToHeader rune %c - %d", r, r)
		if r < 33 || r > 126 {
			log.Debugf("%s.header.claims %s includes character %c, replacing with '-'", Branding.CcName, was, r)
			claim = strings.Replace(claim, string(r), "-", 1)
		}
	}
	claim = Cfg.Headers.ClaimHeader + http.CanonicalHeaderKey(claim)
	if claim != was {
		log.Infof("%s.header.claims %s will be forwarded downstream in the Header %s", Branding.CcName, was, claim)
		log.Debugf("nginx will popultate the variable $auth_resp_%s", strings.ReplaceAll(strings.ToLower(claim), "-", "_"))
	}
	// log.Errorf("%s.header.claims %s will be forwarded in the Header %s", Branding.CcName, was, claim)
	return claim, nil

}

// fix the claims headers
// https://github.com/vouch/vouch-proxy/issues/183

func cleanClaimsHeaders() error {
	cleanedHeaders := make(map[string]string)
	for _, claim := range Cfg.Headers.Claims {
		header, err := claimToHeader(claim)
		if err != nil {
			return err
		}
		cleanedHeaders[claim] = header
	}
	Cfg.Headers.ClaimsCleaned = cleanedHeaders
	return nil
}
