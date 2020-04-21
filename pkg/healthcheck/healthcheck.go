package healthcheck

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"go.uber.org/zap"
)

var log *zap.SugaredLogger

func configure() {
	// cfg.ConfigureLogger()
	log = cfg.Logging.Logger
	if !cfg.Cfg.Testing {
		cfg.Logging.AtomicLogLevel.SetLevel(zap.ErrorLevel)
	}
}

// CheckAndExitIfIsHealthCheck healthcheck is a command line flag `-healthcheck`
func CheckAndExitIfIsHealthCheck() {

	if *cfg.CmdLine.IsHealthCheck {
		configure()
		healthcheck()
	}
}

func healthcheck() {
	url := fmt.Sprintf("http://%s:%d/healthcheck", cfg.Cfg.Listen, cfg.Cfg.Port)
	log.Debug("Invoking healthcheck on URL ", url)
	resp, err := http.Get(url)
	if err == nil {
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {
			var result map[string]interface{}
			jsonErr := json.Unmarshal(body, &result)
			if jsonErr == nil {
				if result["ok"] == true {
					log.Debugf("Healthcheck succeeded for %s", url)
					os.Exit(0)
				}
			}
		}
	}
	log.Errorf("Healthcheck failed for %s", url)
	os.Exit(1)
}
