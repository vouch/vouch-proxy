/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package capturewriter

import (
	"net/http"
	"strconv"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"go.uber.org/zap"
)

// we wrap ResponseWriter so that we can store the StatusCode
// and then pull it out later for logging
// https://play.golang.org/p/wPHaX9DH-Ik

var logger *zap.SugaredLogger
var log *zap.Logger

// Configure see main.go configure()
func Configure() {
	logger = cfg.Logging.Logger
	log = cfg.Logging.FastLogger
}

// CaptureWriter extends http.ResponseWriter
type CaptureWriter struct {
	http.ResponseWriter
	StatusCode int
}

func (w *CaptureWriter) Write(b []byte) (int, error) {
	if w.StatusCode == 0 {
		w.StatusCode = 200
		// log.Debug("CaptureWriter.Write set w.StatusCode " + strconv.Itoa(w.StatusCode))
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
