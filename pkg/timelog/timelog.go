package timelog

import (
	"context"
	"net/http"
	"time"

	lctx "github.com/LassoProject/lasso/pkg/context"

	log "github.com/Sirupsen/logrus"
	// "github.com/mattn/go-isatty"
)

var (
	green   = string([]byte{27, 91, 57, 55, 59, 52, 50, 109})
	white   = string([]byte{27, 91, 57, 48, 59, 52, 55, 109})
	yellow  = string([]byte{27, 91, 57, 55, 59, 52, 51, 109})
	red     = string([]byte{27, 91, 57, 55, 59, 52, 49, 109})
	blue    = string([]byte{27, 91, 57, 55, 59, 52, 52, 109})
	magenta = string([]byte{27, 91, 57, 55, 59, 52, 53, 109})
	cyan    = string([]byte{27, 91, 57, 55, 59, 52, 54, 109})
	reset   = string([]byte{27, 91, 48, 109})
)

// HERE you left off trying to figure out how to implement middleware in gorilla mux
func TimeLog(nextHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Request received : %v\n", r)
		start := time.Now()

		// make the call
		ctx := context.Background()
		nextHandler.ServeHTTP(w, r.WithContext(ctx))

		// Stop timer
		end := time.Now()
		log.Debug("Request handled successfully")

		latency := end.Sub(start)
		clientIP := r.RemoteAddr
		method := r.Method

		// var statusCode int
		// var statusColor string
		statusCode := ctx.Value(lctx.StatusCode)
		// TODO: this just doesn't seem to work, how can we get the statusCode from the context?
		// log.Debugf("statuscode: %v", statusCode)
		if statusCode == nil {
			statusCode = 200
		}
		statusColor := colorForStatus(statusCode.(int))

		path := r.URL.Path
		host := r.Host
		referer := r.Header.Get("Referer")

		log.Infof("|%s %3d %s| %13v | %s | %s %s %s | %s",
			statusColor, statusCode, reset,
			latency,
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
