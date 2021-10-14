/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package responses

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"go.uber.org/zap"
	"golang.org/x/net/context"
)

// Index variables passed to index.tmpl
type Index struct {
	Msg          string
	TestURLs     []string
	Testing      bool
	DocumentRoot string
}

var (
	indexTemplate *template.Template
	errorTemplate *template.Template
	log           *zap.SugaredLogger
	fastlog       *zap.Logger

	errNotAuthorized = errors.New("not authorized")
)

// Configure see main.go configure()
func Configure() {
	log = cfg.Logging.Logger
	fastlog = cfg.Logging.FastLogger

	log.Debugf("responses.Configure() attempting to parse embedded templates")
	indexTemplate = template.Must(template.ParseFS(cfg.Templates, "templates/index.tmpl"))
}

// RenderIndex render the response as an HTML page, mostly used in testing
func RenderIndex(w http.ResponseWriter, msg string) {
	if err := indexTemplate.Execute(w, &Index{Msg: msg, TestURLs: cfg.Cfg.TestURLs, Testing: cfg.Cfg.Testing, DocumentRoot: cfg.Cfg.DocumentRoot}); err != nil {
		log.Error(err)
	}
}

// renderError html error page
// something terse for the end user
func renderError(w http.ResponseWriter, msg string, status int) {
	log.Debugf("rendering error for user: %s", msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := indexTemplate.Execute(w, &Index{Msg: msg, DocumentRoot: cfg.Cfg.DocumentRoot}); err != nil {
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

// Redirect302 redirect to the specified rURL
func Redirect302(w http.ResponseWriter, r *http.Request, rURL string) {
	if cfg.Cfg.Testing {
		cfg.Cfg.TestURLs = append(cfg.Cfg.TestURLs, rURL)
		RenderIndex(w, "302 redirect to: "+rURL)
		return
	}
	http.Redirect(w, r, rURL, http.StatusFound)
}

// Error400 Bad Request
func Error400(w http.ResponseWriter, r *http.Request, e error) {
	cancelClearSetError(w, r, e)
	renderError(w, "400 Bad Request", http.StatusBadRequest)
}

// Error401 Unauthorized, the standard error returned when failing /validate
// this is captured by nginx, which converts the 401 into 302 to the login page
func Error401(w http.ResponseWriter, r *http.Request, e error) {
	cancelClearSetError(w, r, e)
	http.Error(w, e.Error(), http.StatusUnauthorized)
	// renderError(w, "401 Unauthorized")
}

// Error401HTTP
func Error401HTTP(w http.ResponseWriter, r *http.Request, e error) {
	cancelClearSetError(w, r, e)
	renderError(w, e.Error(), http.StatusUnauthorized)
}

// Error403 Forbidden
// if there's an error during /auth or if they don't pass validation in /auth
func Error403(w http.ResponseWriter, r *http.Request, e error) {
	cancelClearSetError(w, r, e)
	renderError(w, "403 Forbidden", http.StatusForbidden)
}

// Error500 Internal Error
// something is not right, hopefully this never happens
func Error500(w http.ResponseWriter, r *http.Request, e error) {
	cancelClearSetError(w, r, e)
	log.Infof("If this error persists it may be worthy of a bug report but please check your setup first.  See the README at %s", cfg.Branding.URL)
	renderError(w, "500 - Internal Server Error", http.StatusInternalServerError)
}

// cancelClearSetError convenience method to keep it DRY
func cancelClearSetError(w http.ResponseWriter, r *http.Request, e error) {
	log.Warn(e)
	cookie.ClearCookie(w, r)
	w.Header().Set(cfg.Cfg.Headers.Error, e.Error())
	addErrandCancelRequest(r)
}

// cfg.ErrCtx is tested by `jwtmanager.JWTCacheHandler`
func addErrandCancelRequest(r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	ctx = context.WithValue(ctx, cfg.ErrCtxKey, true)
	*r = *r.Clone(ctx)
	cancel() // we're done
	return
}
