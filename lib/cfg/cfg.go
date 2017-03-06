package cfg

import (
	"os"

	log "github.com/Sirupsen/logrus"

	"github.com/spf13/viper"
)

func init() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(os.Getenv("LASSO_ROOT") + "config")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatalf("Fatal error config file: %s", err.Error())
		panic(err)
	}
}

func UnmarshalKey(key string, rawVal interface{}) error {
	return viper.UnmarshalKey(key, rawVal)
}

func Get(key string) string {
	return viper.GetString(key)
}
