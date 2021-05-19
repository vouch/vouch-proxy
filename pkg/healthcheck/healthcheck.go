/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

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
	log.Debugf("Invoking healthcheck on %s", url)
	// #nosec - turn off gosec checking which flags `http.Get(url)`
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
