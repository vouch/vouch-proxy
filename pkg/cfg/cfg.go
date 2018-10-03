package cfg

import (
	"errors"
	"flag"
	"os"

	log "github.com/Sirupsen/logrus"

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
		QueryString string `mapstructure:"querystring"`
		Redirect    string `mapstructure:"redirect"`
	}
	DB struct {
		File string `mapstructure:"file"`
	}
	Session struct {
		Name string `mapstructure:"name"`
	}
	TestURL string `mapstructure:"test_url"`
	Testing bool   `mapstructure:"testing"`
}

// Cfg the main exported config variable
var Cfg CfgT

// RequiredOptions must have these fields set for minimum viable config
var RequiredOptions = []string{"lasso.port", "lasso.listen", "lasso.jwt.secret", "lasso.db.file", "oauth.provider", "oauth.client_id", "oauth.client_secret"}

func init() {
	ParseConfig()
	var ll = flag.String("loglevel", Cfg.LogLevel, "enable debug log output")
	flag.Parse()
	if *ll == "debug" {
		log.SetLevel(log.DebugLevel)
		log.Debug("logLevel set to debug")
	}
	log.Debug(viper.AllSettings())
}

// ParseConfig parse the config file
func ParseConfig() {
	log.Info("opening config")
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
	// nested defaults is currently *broken*
	// https://github.com/spf13/viper/issues/309
	// viper.SetDefault("listen", "0.0.0.0")
	// viper.SetDefault(Cfg.Port, 9090)
	// viper.SetDefault("Headers.SSO", "X-Lasso-Token")
	// viper.SetDefault("Headers.Redirect", "X-Lasso-Requested-URI")
	// viper.SetDefault("Cookie.Name", "Lasso")
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
