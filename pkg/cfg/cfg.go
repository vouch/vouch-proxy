package cfg

import (
	"os"

	log "github.com/Sirupsen/logrus"

	"github.com/spf13/viper"
)

// Cfg lasso jwt cookie configuration
type CfgT struct {
	LogLevel        string   `mapstructure:"logLevel"`
	Listen          string   `mapstructure:"listen"`
	Port            int      `mapstructure:"port"`
	Domains         []string `mapstructure:"domains"`
	PreferredDomain string   `mapstructre:"preferredDomain"`
	JWT             struct {
		MaxAge int    `mapstructure:"maxAge"`
		Issuer string `mapstructure:"issuer"`
		Secret []byte `mapstructure:"secret"`
	}
	Cookie struct {
		Name     string `mapstructure:"name"`
		Secure   bool   `mapstructure:"secure"`
		HTTPOnly bool   `mapstructure:"httpOnly"`
	}
	Headers struct {
		SSO      string `mapstructure:"sso"`
		Redirect string `mapstructure:"redirect"`
	}
	DB struct {
		File string `mapstructure:"file"`
	}
	Session struct {
		Name string `mapstructure:"name"`
	}
}

var Cfg CfgT

func init() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(os.Getenv("LASSO_ROOT") + "config")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatalf("Fatal error config file: %s", err.Error())
		panic(err)
	}
	UnmarshalKey("lasso", &Cfg)

}

func UnmarshalKey(key string, rawVal interface{}) error {
	return viper.UnmarshalKey(key, rawVal)
}

func Get(key string) string {
	return viper.GetString(key)
}
