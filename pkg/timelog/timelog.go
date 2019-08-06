package timelog

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/response"
)

var (
	req        = int64(0)
	avgLatency = int64(0)

	log = cfg.Cfg.Logger
)

// TimeLog records how long it takes to process the http request and produce the response (latency)
func TimeLog(nextHandler http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Request received : %v", r)
		start := time.Now()

		// make the call
		v := response.CaptureWriter{ResponseWriter: w, StatusCode: 0}
		ctx := context.Background()
		nextHandler.ServeHTTP(&v, r.WithContext(ctx))

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)
		req++
		avgLatency = avgLatency + ((int64(latency) - avgLatency) / req)
		log.Debugf("Request handled successfully: %v", v.GetStatusCode())
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
	}
}
