package response

import "net/http"
import log "github.com/Sirupsen/logrus"

// we wrap ResponseWriter so that we can store the StatusCode
// and then pull it out later for logging
// https://play.golang.org/p/wPHaX9DH-Ik

// CaptureWriter extends http.ResponseWriter
type CaptureWriter struct {
	http.ResponseWriter
	StatusCode int
}

func (w *CaptureWriter) Write(b []byte) (int, error) {
	if w.StatusCode == 0 {
		w.StatusCode = 200
		log.Debugf("set w.StatusCode %d", w.StatusCode)
	}
	log.Debugf("CaptureWriter.Write code %d", w.StatusCode)
	return w.ResponseWriter.Write(b)
}

// Header calls http.Writer.Header()
func (w *CaptureWriter) Header() http.Header {
	log.Debugf("CaptureWriter.Header code %d", w.StatusCode)
	return w.ResponseWriter.Header()
}

// WriteHeader calls http.Writer.WriteHeader(code)
func (w *CaptureWriter) WriteHeader(code int) {
	w.StatusCode = code
	log.Debugf("CaptureWriter.WriteHeader code %d", w.StatusCode)
	w.ResponseWriter.WriteHeader(code)
}

// GetStatusCode return w.StatusCode
func (w *CaptureWriter) GetStatusCode() int {
	return w.StatusCode
}
