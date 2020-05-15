/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package responses

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"go.uber.org/zap"
)

// Index variables passed to index.tmpl
type Index struct {
	Msg      string
	TestURLs []string
	Testing  bool
}

var (
	indexTemplate *template.Template
	log           *zap.SugaredLogger
	fastlog       *zap.Logger
)

// Configure see main.go configure()
func Configure() {
	log = cfg.Logging.Logger
	fastlog = cfg.Logging.FastLogger

	log.Debugf("responses.Configure() attempting to parse templates with cfg.RootDir: %s", cfg.RootDir)
	indexTemplate = template.Must(template.ParseFiles(filepath.Join(cfg.RootDir, "templates/index.tmpl")))

}

// RenderIndex render the response as an HTML page, mostly used in testing
func RenderIndex(w http.ResponseWriter, msg string) {
	if err := indexTemplate.Execute(w, &Index{Msg: msg, TestURLs: cfg.Cfg.TestURLs, Testing: cfg.Cfg.Testing}); err != nil {
		log.Error(err)
	}
}

// OK200 returns "200 OK"
func OK200(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("200 OK\n"))
	if err != nil {
		log.Error(err)
	}
}

// Redirect302 302 redirect to the specificed rURL
func Redirect302(w http.ResponseWriter, r *http.Request, rURL string) {
	if cfg.Cfg.Testing {
		cfg.Cfg.TestURLs = append(cfg.Cfg.TestURLs, rURL)
		RenderIndex(w, "302 redirect to: "+rURL)
		return
	}
	http.Redirect(w, r, rURL, http.StatusFound)
}

// Error400 Bad Request
// returned when the requesed url param for /login or /logout is bd
func Error400(w http.ResponseWriter, r *http.Request, e error) {
	log.Error(e)
	cookie.ClearCookie(w, r)
	w.Header().Set("X-Vouch-Error", e.Error())
	http.Error(w, e.Error(), http.StatusBadRequest)
}

// Error401 Unauthorized the standard error
// this is captured by nginx, which converts the 401 into 302 to the login page
func Error401(w http.ResponseWriter, r *http.Request, e error) {
	log.Error(e)
	cookie.ClearCookie(w, r)
	w.Header().Set("X-Vouch-Error", e.Error())
	http.Error(w, e.Error(), http.StatusUnauthorized)
}

// Error401na send 401 not authorized
func Error401na(w http.ResponseWriter, r *http.Request) {
	Error401(w, r, fmt.Errorf("not authorized"))
}

// Error403 Forbidden
// if there's an error during /auth or if they don't pass validation in /auth
func Error403(w http.ResponseWriter, r *http.Request, e error) {
	log.Error(e)
	cookie.ClearCookie(w, r)
	w.Header().Set("X-Vouch-Error", e.Error())
	http.Error(w, e.Error(), http.StatusForbidden)
}
