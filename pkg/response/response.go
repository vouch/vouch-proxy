package response

import (
	"net/http"
	"strconv"

	"github.com/vouch/vouch-proxy/pkg/cfg"
)

// we wrap ResponseWriter so that we can store the StatusCode
// and then pull it out later for logging
// https://play.golang.org/p/wPHaX9DH-Ik

var log = cfg.Cfg.FastLogger

// CaptureWriter extends http.ResponseWriter
type CaptureWriter struct {
	http.ResponseWriter
	StatusCode int
}

func (w *CaptureWriter) Write(b []byte) (int, error) {
	if w.StatusCode == 0 {
		w.StatusCode = 200
		log.Debug("CaptureWriter.Write set w.StatusCode " + strconv.Itoa(w.StatusCode))
	}
	return w.ResponseWriter.Write(b)
}

// Header calls http.Writer.Header()
func (w *CaptureWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

// WriteHeader calls http.Writer.WriteHeader(code)
func (w *CaptureWriter) WriteHeader(code int) {
	w.StatusCode = code
	log.Debug("CaptureWriter.Write set w.StatusCode " + strconv.Itoa(w.StatusCode))
	w.ResponseWriter.WriteHeader(code)
}

// GetStatusCode return w.StatusCode
func (w *CaptureWriter) GetStatusCode() int {
	return w.StatusCode
}
