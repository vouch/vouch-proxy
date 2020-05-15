package cfg

import (
	"errors"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

// Config vouch jwt cookie configuration
type deprecatedVouch struct {
	LogLevel      string   `mapstructure:"logLevel"`
	WhiteList     []string `mapstructure:"whitelist"`
	TeamWhiteList []string `mapstructure:"teamWhitelist"`
	AllowAllUsers bool     `mapstructure:"allowAllUsers"`
	PublicAccess  bool     `mapstructure:"publicAccess"`
	JWT           struct {
		MaxAge int `mapstructure:"maxAge"` // in minutes
	}
	Cookie struct {
		HTTPOnly bool   `mapstructure:"httpOnly"`
		MaxAge   int    `mapstructure:"maxage"`
		SameSite string `mapstructure:"sameSite"`
	}

	// Headers struct {
	// 	QueryString   string            `mapstructure:"querystring"`
	// 	ClaimHeader   string            `mapstructure:"claimheader"`
	// 	AccessToken   string            `mapstructure:"accesstoken"`
	// 	IDToken       string            `mapstructure:"idtoken"`
	// }

}

// oauth config items endoint for access
type deprecatedOauthConfig struct {
	PreferredDomain string `mapstructure:"preferredDomain"`
}

type deprecated struct {
	Vouch deprecatedVouch
	OAuth deprecatedOauthConfig
}

var errHasDeprecatedName = errors.New("config element has been deprecated")

// use viper and mapstructure check to see if
// https://pkg.go.dev/github.com/spf13/viper@v1.6.3?tab=doc#Unmarshal
// https://pkg.go.dev/github.com/mitchellh/mapstructure?tab=doc#DecoderConfig
func checkDeprecated() error {
	md := &mapstructure.Metadata{}
	opt := func(dc *mapstructure.DecoderConfig) {
		dc.Metadata = md
	}

	q := &deprecated{}

	viper.Unmarshal(q, opt)

	log.Debugf("md: %+v", md)

	noproblem := map[string]bool{
		"Vouch": true,
		"OAuth": true,
	}

	found := false
	for _, k := range md.Keys {
		if noproblem[k] {
			continue
		}
		found = true
		for np := range noproblem {
			k = strings.TrimPrefix(k, np+".")
		}
		log.Warnf("Vouch Proxy now prefers snake_case for config items.  Please see `config.yml_example` for the new name for: %s", k)
	}
	if found {
		return errHasDeprecatedName
	}

	return nil
}
