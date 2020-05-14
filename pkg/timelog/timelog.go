/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package timelog

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/vouch/vouch-proxy/pkg/capturewriter"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"go.uber.org/zap"
)

var (
	req        = int64(0)
	avgLatency = int64(0)
	log        *zap.SugaredLogger
)

// Configure see main.go configure()
func Configure() {
	log = cfg.Logging.Logger

	capturewriter.Configure()

}

// TimeLog records how long it takes to process the http request and produce the response (latency)
func TimeLog(nextHandler http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// log.Debugf("Request received : %v", r)
		start := time.Now()

		// make the call
		v := capturewriter.CaptureWriter{ResponseWriter: w, StatusCode: 0}
		ctx := context.Background()
		nextHandler.ServeHTTP(&v, r.WithContext(ctx))

		// Stop timer
		end := time.Now()

		go func() {
			latency := end.Sub(start)
			req++
			avgLatency = avgLatency + ((int64(latency) - avgLatency) / req)
			// log.Debugf("Request handled successfully: %v", v.GetStatusCode())
			var statusCode = v.GetStatusCode()

			path := r.URL.Path
			host := r.Host
			referer := r.Header.Get("Referer")
			clientIP := r.RemoteAddr
			method := r.Method

			log.Infow(fmt.Sprintf("|%d| %10v %s", statusCode, time.Duration(latency), path),
				"statusCode", statusCode,
				"request", req,
				"latency", time.Duration(latency),
				"avgLatency", time.Duration(avgLatency),
				"ipPort", clientIP,
				"method", method,
				"host", host,
				"path", path,
				"referer", referer,
			)
		}()

	}
}
