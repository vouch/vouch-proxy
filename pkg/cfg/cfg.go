/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/kelseyhightower/envconfig"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	securerandom "github.com/theckman/go-securerandom"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config vouch jwt cookie configuration
// Note to developers!  Any new config elements
// should use `snake_case` such as `post_logout_redirect_uris`
// in certain situations you'll need to add both a `mapstructure` tag used by viper
// as well as a `envconfig` tag used by https://github.com/kelseyhightower/envconfig
// though most of the time envconfig will use the struct key's name: VOUCH_PORT VOUCH_JWT_MAXAGE
// default values should be set in .defaults.yml
type Config struct {
	LogLevel      string   `mapstructure:"logLevel"`
	Listen        string   `mapstructure:"listen"`
	Port          int      `mapstructure:"port"`
	SocketMode    int      `mapstructure:"socket_mode"`
	SocketGroup   string   `mapstructure:"socket_group"`
	DocumentRoot  string   `mapstructure:"document_root" envconfig:"document_root"`
	WriteTimeout  int      `mapstructure:"writeTimeout"`
	ReadTimeout   int      `mapstructure:"readTimeout"`
	IdleTimeout   int      `mapstructure:"idleTimeout"`
	Domains       []string `mapstructure:"domains"`
	WhiteList     []string `mapstructure:"whitelist"`
	TeamWhiteList []string `mapstructure:"teamWhitelist"`
	AllowAllUsers bool     `mapstructure:"allowAllUsers"`
	PublicAccess  bool     `mapstructure:"publicAccess"`
	TLS           struct {
		Cert    string `mapstructure:"cert"`
		Key     string `mapstructure:"key"`
		Profile string `mapstructure:"profile"`
	}
	JWT struct {
		SigningMethod  string `mapstructure:"signing_method"`
		MaxAge         int    `mapstructure:"maxAge"` // in minutes
		Issuer         string `mapstructure:"issuer"`
		Secret         string `mapstructure:"secret"`
		PrivateKeyFile string `mapstructure:"private_key_file"`
		PublicKeyFile  string `mapstructure:"public_key_file"`
		Compress       bool   `mapstructure:"compress"`
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
		Sub           string            `mapstructure:"sub"`
		JWT           string            `mapstructure:"jwt"`
		User          string            `mapstructure:"user"`
		QueryString   string            `mapstructure:"querystring"`
		Redirect      string            `mapstructure:"redirect"`
		Success       string            `mapstructure:"success"`
		Error         string            `mapstructure:"error"`
		ClaimHeader   string            `mapstructure:"claimheader"`
		Claims        []string          `mapstructure:"claims"`
		AccessToken   string            `mapstructure:"accesstoken"`
		IDToken       string            `mapstructure:"idtoken"`
		ClaimsCleaned map[string]string // the rawClaim is mapped to the actual claims header
	}
	Session struct {
		Name   string `mapstructure:"name"`
		MaxAge int    `mapstructure:"maxage"`
		Key    string `mapstructure:"key"`
	}
	TestURL            string   `mapstructure:"test_url"`
	TestURLs           []string `mapstructure:"test_urls"`
	Testing            bool     `mapstructure:"testing"`
	LogoutRedirectURLs []string `mapstructure:"post_logout_redirect_uris" envconfig:"post_logout_redirect_uris"`
}

type branding struct {
	LCName   string // lower case vouch
	UCName   string // UPPER CASE VOUCH
	CcName   string // camelCase Vouch
	FullName string // Vouch Proxy
	URL      string // https://github.com/vouch/vouch-proxy
}

var (
	// Branding that's our name
	Branding = branding{"vouch", "VOUCH", "Vouch", "Vouch Proxy", "https://github.com/vouch/vouch-proxy"}

	// RootDir is where Vouch Proxy looks for ./config/config.yml and ./data
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

	errConfigNotFound = errors.New("configuration file not found")
	// TODO: audit errors and use errConfigIsBad
	// errConfigIsBad    = errors.New("configuration file is malformed")

	// Templates are loaded from the file system with a go:embed directive in main.go
	Templates fs.FS

	// Defaults are loaded from the file system with a go:embed directive in main.go
	Defaults embed.FS
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

	// ErrCtxKey set or check the http request context to see if it has errored
	// see `responses.Error401` and `jwtmanager.JWTCacheHandler` for example
	ErrCtxKey ctxKey = 0
)

// use a typed ctxKey to avoid context key collision
// https://blog.golang.org/context#TOC_3.2.
type ctxKey int

// Configure called at the very top of main()
// the order of config follows the Viper conventions...
//
// The priority of the sources is the following:
// 1. command line flags
// 2. env. variables
// 3. config file
// 4. defaults
//
// so we process these in backwards order (defaults then config file)
func Configure() {
	logger.Info("Copyright 2020-2023 the " + Branding.FullName + " Authors")
	logger.Warn(Branding.FullName + " is free software with ABSOLUTELY NO WARRANTY.")

	Logging.configureFromCmdline()

	setRootDir()
	secretFile = filepath.Join(RootDir, "config/secret")

	// bail if we're testing
	if flag.Lookup("test.v") != nil {
		log.Debug("`go test` detected, not loading regular config")
		Logging.setLogLevel(zap.WarnLevel)
		return
	}

	setDefaults()
	configFileErr := parseConfigFile()

	didConfigFromEnv := configureFromEnv()

	if !didConfigFromEnv && configFileErr != nil {
		// then it's probably config file not found
		logSysInfo()
		log.Fatal(configFileErr)
	}

	fixConfigOptions()
	Logging.configure()

	if err := configureOauth(); err == nil {
		setProviderDefaults()
	}
	if err := cleanClaimsHeaders(); err != nil {
		log.Fatalf("%w: %w", configFileErr, err)
	}
	if *CmdLine.port != -1 {
		Cfg.Port = *CmdLine.port
	}
	logConfigIfDebug()
}

// using envconfig
// https://github.com/kelseyhightower/envconfig
func configureFromEnv() bool {
	preEnvConfig := *Cfg
	err := envconfig.Process(Branding.UCName, Cfg)
	if err != nil {
		log.Fatal(err.Error())
	}
	preEnvGenOAuth := *GenOAuth

	err = envconfig.Process("OAUTH", GenOAuth)
	if err != nil {
		log.Fatal(err.Error())
	}
	// did anything change?
	if !reflect.DeepEqual(preEnvConfig, *Cfg) ||
		!reflect.DeepEqual(preEnvGenOAuth, *GenOAuth) {

		// set logLevel before calling Log.Debugf()
		if preEnvConfig.LogLevel != Cfg.LogLevel {
			Logging.setLogLevelString(Cfg.LogLevel)
		}
		// log.Debugf("preEnvConfig %+v", preEnvConfig)
		log.Infof("%s configuration set from Environmental Variables", Branding.FullName)
		return true
	}
	return false
}

// ValidateConfiguration confirm the Configuration is valid
func ValidateConfiguration() error {
	if Cfg.Testing {
		// Logging.setLogLevel(zap.DebugLevel)
		Logging.setDevelopmentLogger()
	}

	return basicTest()
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
	}
}

// parseConfig parse the config file
func parseConfigFile() error {
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

		return fmt.Errorf("%w: %s", errConfigNotFound, err)
	}

	if err = checkConfigFileWellFormed(); err != nil {
		log.Error("configuration error: config file should have only two top level elements: `vouch` and `oauth`.  These and other syntax errors follow...")
		log.Error(err)
		log.Error("continuing... (maybe you know what you're doing :)")
	}

	if err = UnmarshalKey(Branding.LCName, &Cfg); err != nil {
		log.Error(err)
	}
	// don't log the secret!
	// log.Debugf("secret: %s", string(Cfg.JWT.Secret))
	return nil
}

// consolidate config related Log.Debugf() calls so that they can be placed *after* we set the logLevel
func logConfigIfDebug() {
	log.Debugf("cfg.RootDir: %s", RootDir)
	// log.Debugf("viper settings %+v", viper.AllSettings())

	// Mask sensitive configuration items before logging
	maskedCfg := *Cfg
	if len(Cfg.Session.Key) != 0 {
		maskedCfg.Session.Key = "XXXXXXXX"
	}
	if len(Cfg.JWT.Secret) != 0 {
		maskedCfg.JWT.Secret = "XXXXXXXX"
	}
	log.Debugf("Cfg %+v", maskedCfg)

	maskedGenOAuth := *GenOAuth
	maskedGenOAuth.ClientID = "12345678"
	maskedGenOAuth.ClientSecret = "XXXXXXXX"
	log.Debugf("cfg.GenOauth %+v", maskedGenOAuth)
}

func fixConfigOptions() {
	if Cfg.Cookie.MaxAge > Cfg.JWT.MaxAge {
		log.Warnf("setting `%s.cookie.maxage` to `%s.jwt.maxage` value of %d minutes (curently set to %d minutes)", Branding.LCName, Branding.LCName, Cfg.JWT.MaxAge, Cfg.Cookie.MaxAge)
		Cfg.Cookie.MaxAge = Cfg.JWT.MaxAge
	}

	// headers defaults
	if !viper.IsSet(Branding.LCName + ".headers.redirect") {
		Cfg.Headers.Redirect = "X-" + Branding.CcName + "-Requested-URI"
	}

	// jwt defaults
	if strings.HasPrefix(Cfg.JWT.SigningMethod, "HS") && len(Cfg.JWT.Secret) == 0 {
		Cfg.JWT.Secret = getOrGenerateJWTSecret()
	}

	if len(Cfg.JWT.PrivateKeyFile) > 0 && !path.IsAbs(Cfg.JWT.PrivateKeyFile) {
		Cfg.JWT.PrivateKeyFile = path.Join(RootDir, Cfg.JWT.PrivateKeyFile)
	}

	if len(Cfg.JWT.PublicKeyFile) > 0 && !path.IsAbs(Cfg.JWT.PublicKeyFile) {
		Cfg.JWT.PublicKeyFile = path.Join(RootDir, Cfg.JWT.PublicKeyFile)
	}

	if len(Cfg.Session.Key) == 0 {
		log.Warn("generating random session.key")
		rstr, err := securerandom.Base64OfBytes(base64Bytes)
		if err != nil {
			log.Fatal(err)
		}
		Cfg.Session.Key = rstr
	}

	if Cfg.TestURL != "" {
		Cfg.TestURLs = append(Cfg.TestURLs, Cfg.TestURL)
	}

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

	if GenOAuth.Provider == "" {
		return errors.New("configuration error: required configuration option 'oauth.provider' is not set")
	}
	if GenOAuth.ClientID == "" {
		return errors.New("configuration error: required configuration option 'oauth.client_id' is not set")
	}

	// Domains is required _unless_ Cfg.AllowAllUsers is set
	if (!Cfg.AllowAllUsers && len(Cfg.Domains) == 0) ||
		(Cfg.AllowAllUsers && len(Cfg.Domains) > 0) {
		return fmt.Errorf("configuration error: either one of %s or %s needs to be set (but not both)", Branding.LCName+".domains", Branding.LCName+".allowAllUsers")
	}

	// issue a warning if the secret is too small
	log.Debugf("vouch.jwt.secret is %d characters long", len(Cfg.JWT.Secret))

	allowedSigningMethods := map[string]struct{}{
		"HS256": {}, "HS384": {}, "HS512": {}, // HMAC
		"RS256": {}, "RS384": {}, "RS512": {}, // RSA
		"ES256": {}, "ES384": {}, "ES512": {}, // ECDSA
	}
	if _, ok := allowedSigningMethods[Cfg.JWT.SigningMethod]; !ok {
		return fmt.Errorf("configuration error: %s.jwt.signing_method value not allowed", Branding.LCName)
	}

	if strings.HasPrefix(Cfg.JWT.SigningMethod, "HS") {
		if len(Cfg.JWT.PublicKeyFile) > 0 {
			return fmt.Errorf("%s.jwt.public_key_file should not be set when using signing method %s", Branding.LCName, Cfg.JWT.SigningMethod)
		}

		if len(Cfg.JWT.PrivateKeyFile) > 0 {
			return fmt.Errorf("%s.jwt.private_key_file should not be set when using signing method %s", Branding.LCName, Cfg.JWT.SigningMethod)
		}

		if len(Cfg.JWT.Secret) < minBase64Length {
			log.Errorf("Your secret is too short! (%d characters long). Please consider deleting %s to automatically generate a secret of %d characters",
				len(Cfg.JWT.Secret),
				Branding.LCName+".jwt.secret",
				minBase64Length)
		}
	}

	if strings.HasPrefix(Cfg.JWT.SigningMethod, "RS") || strings.HasPrefix(Cfg.JWT.SigningMethod, "ES") {
		if len(Cfg.JWT.Secret) > 0 {
			return fmt.Errorf("%s.jwt.secret should not be set when using signing method %s", Branding.LCName, Cfg.JWT.SigningMethod)
		}

		if len(Cfg.JWT.PublicKeyFile) == 0 {
			return fmt.Errorf("%s.jwt.public_key_file needs to be set for signing method %s", Branding.LCName, Cfg.JWT.SigningMethod)
		}

		if len(Cfg.JWT.PrivateKeyFile) == 0 {
			return fmt.Errorf("%s.jwt.private_key_file needs to be set for signing method %s", Branding.LCName, Cfg.JWT.SigningMethod)
		}
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

	// check tls config
	if Cfg.TLS.Key != "" && Cfg.TLS.Cert == "" {
		return fmt.Errorf("configuration error: TLS certificate file not provided but TLS key is set (%s)", Cfg.TLS.Key)
	}
	if Cfg.TLS.Cert != "" && Cfg.TLS.Key == "" {
		return fmt.Errorf("configuration error: TLS key file not provided but TLS certificate is set (%s)", Cfg.TLS.Cert)
	}

	return nil
}

// setDefaults set default options for most items from `.defaults.yml` in the root dir
func setDefaults() {

	// viper.SetConfigName(".defaults")
	viper.SetConfigType("yaml")
	// viper.AddConfigPath(RootDir)
	// viper.ReadInConfig()
	d, err := Defaults.ReadFile(".defaults.yml")
	if err != nil {
		log.Fatal(err)
	}
	viper.ReadConfig(bytes.NewBuffer(d))
	if err := viper.UnmarshalKey(Branding.LCName, &Cfg); err != nil {
		log.Error(err)
	}
	// keep this here for development, we're still pre configurating of LogLevel
	// log.Debugf("setDefaults from .defaults.yml %+v", Cfg)

	// bare minimum for healthcheck achieved
	if *CmdLine.IsHealthCheck {
		return
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
		log.Debugf("nginx will populate the variable $auth_resp_%s", strings.ReplaceAll(strings.ToLower(claim), "-", "_"))
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

// InitForTestPurposes is called by most *_testing.go files in Vouch Proxy
func InitForTestPurposes() {
	InitForTestPurposesWithProvider("")
}

// InitForTestPurposesWithProvider just for testing
func InitForTestPurposesWithProvider(provider string) {
	Cfg = &Config{} // clear it out since we're called multiple times from subsequent tests

	Logging.setLogLevel(zapcore.InfoLevel)
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

	// can't use setDefaults for testing which is go:embed based so we do it the old way
	// setDefaults()
	viper.SetConfigName(".defaults")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(RootDir)
	viper.ReadInConfig()
	if err := UnmarshalKey(Branding.LCName, &Cfg); err != nil {
		log.Error(err)
	}

	// this also mimics the go:embed testing setup
	Templates = os.DirFS(RootDir)

	if err := parseConfigFile(); err != nil {
		log.Error(err)
	}
	configureFromEnv()
	if err := configureOauth(); err == nil {
		setProviderDefaults()
	}
	fixConfigOptions()
	// setDevelopmentLogger()

	// Needed to override the provider, which is otherwise set via yml
	if provider != "" {
		GenOAuth.Provider = provider
		setProviderDefaults()
	}
	_ = cleanClaimsHeaders()

}

func DecryptionKey() (interface{}, error) {
	if strings.HasPrefix(Cfg.JWT.SigningMethod, "HS") {
		return []byte(Cfg.JWT.Secret), nil
	}

	f, err := os.Open(Cfg.JWT.PublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error opening Key %s: %s", Cfg.JWT.PublicKeyFile, err)
	}

	keyBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("error reading Key: %s", err)
	}

	var key interface{}
	switch {
	case strings.HasPrefix(Cfg.JWT.SigningMethod, "RS"):
		key, err = jwt.ParseRSAPublicKeyFromPEM(keyBytes)
	case strings.HasPrefix(Cfg.JWT.SigningMethod, "ES"):
		key, err = jwt.ParseECPublicKeyFromPEM(keyBytes)
	default:
		// signingMethod should already have been validated, this should not happen
		return nil, fmt.Errorf("unexpected signing method %s", Cfg.JWT.SigningMethod)
	}

	if err != nil {
		return nil, fmt.Errorf("error parsing Key: %s", err)
	}

	return key, nil
}

func SigningKey() (interface{}, error) {
	if strings.HasPrefix(Cfg.JWT.SigningMethod, "HS") {
		return []byte(Cfg.JWT.Secret), nil
	}

	f, err := os.Open(Cfg.JWT.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error opening RSA Key %s: %s", Cfg.JWT.PrivateKeyFile, err)
	}

	keyBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("error reading Key: %s", err)
	}

	var key interface{}
	switch {
	case strings.HasPrefix(Cfg.JWT.SigningMethod, "RS"):
		key, err = jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	case strings.HasPrefix(Cfg.JWT.SigningMethod, "ES"):
		key, err = jwt.ParseECPrivateKeyFromPEM(keyBytes)
	default:
		// We should have validated this before
		return nil, fmt.Errorf("unexpected signing method %s", Cfg.JWT.SigningMethod)
	}

	if err != nil {
		return nil, fmt.Errorf("error parsing Key: %s", err)
	}

	return key, nil
}

// Check that we have read permission for this file
// https://stackoverflow.com/questions/60128401/how-to-check-if-a-file-is-executable-in-go
func canRead(file string) bool {
	stat, err := os.Stat(file)
	if err != nil {
		log.Debug(err)
		return false
	}

	m := stat.Mode()
	return m&0400 != 0
}

// detect if we're in a docker environment
func isDocker() bool {
	return canRead("/.dockerenv")
}

func logSysInfo() {
	if isDocker() {
		log.Warn("detected Docker environment, beware of Docker userid and permissions changes in v0.36.0")
	}
	u, err := user.Current()
	if err != nil {
		log.Error(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		log.Error(err)
	}
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		log.Error(err)
	}
	exe, err := os.Executable()
	if err != nil {
		log.Error(err)
	}
	log.Debugf("%s was executed as '%s' (pid: %d) running as user %s (uid: %s) with group %s (gid: %s)", Branding.FullName, exe, p.Pid, u.Username, u.Uid, g.Name, u.Gid)
}
