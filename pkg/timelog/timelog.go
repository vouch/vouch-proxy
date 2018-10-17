package timelog

import (
	"context"
	"net/http"
	"time"

	"github.com/LassoProject/lasso/pkg/response"

	log "github.com/Sirupsen/logrus"
	// "github.com/mattn/go-isatty"
)

var (
	green      = string([]byte{27, 91, 57, 55, 59, 52, 50, 109})
	white      = string([]byte{27, 91, 57, 48, 59, 52, 55, 109})
	yellow     = string([]byte{27, 91, 57, 55, 59, 52, 51, 109})
	red        = string([]byte{27, 91, 57, 55, 59, 52, 49, 109})
	blue       = string([]byte{27, 91, 57, 55, 59, 52, 52, 109})
	magenta    = string([]byte{27, 91, 57, 55, 59, 52, 53, 109})
	cyan       = string([]byte{27, 91, 57, 55, 59, 52, 54, 109})
	reset      = string([]byte{27, 91, 48, 109})
	req        = int64(0)
	avgLatency = int64(0)
)

// TimeLog records how long it takes to process the http request and produce the response (latency)
func TimeLog(nextHandler http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Request received : %v", r)
		start := time.Now()

		// make the call
		v := response.CaptureWriter{w, 0}
		ctx := context.Background()
		nextHandler.ServeHTTP(&v, r.WithContext(ctx))

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)
		req++
		avgLatency = avgLatency + ((int64(latency) - avgLatency) / req)
		log.Debugf("Request handled successfully: %v", v.GetStatusCode())
		var statusCode = v.GetStatusCode()
		statusColor := colorForStatus(statusCode)

		path := r.URL.Path
		host := r.Host
		referer := r.Header.Get("Referer")

		clientIP := r.RemoteAddr
		method := r.Method

		log.Infof("|%s %3d %s| %d %10v %10v | %s | %s %s %s | %s",
			statusColor, statusCode, reset,
			req, latency, time.Duration(avgLatency),
			clientIP,
			method, host, path,
			referer)
	}
}

func colorForStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return green
	case code >= 300 && code < 400:
		return white
	case code >= 400 && code < 500:
		return yellow
	default:
		return red
	}
}
