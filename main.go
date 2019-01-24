package main

// vouch
// github.com/vouch/vouch-proxy

import (
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/gorilla/mux"

	"github.com/vouch/vouch-proxy/handlers"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/timelog"
	tran "github.com/vouch/vouch-proxy/pkg/transciever"
)

// version and semver get overwritten by build with
// go build -i -v -ldflags="-X main.version=$(git describe --always --long) -X main.semver=v$(git semver get)"

var (
	version   = "undefined"
	builddt   = "undefined"
	host      = "undefined"
	semver    = "undefined"
	branch    = "undefined"
	staticDir = "/static/"
)

func init() {
	// var listen = cfg.Cfg.Listen + ":" + strconv.Itoa(cfg.Cfg.Port)
}

func main() {
	var listen = cfg.Cfg.Listen + ":" + strconv.Itoa(cfg.Cfg.Port)
	log.WithFields(log.Fields{
		// "semver":    semver,
		"version":   version,
		"buildtime": builddt,
		"buildhost": host,
		"branch":    branch,
		"semver":    semver,
		"listen":    listen}).Info("starting " + cfg.Branding.CcName)

	mux := mux.NewRouter()

	authH := http.HandlerFunc(handlers.ValidateRequestHandler)
	mux.HandleFunc("/validate", timelog.TimeLog(authH))
	mux.HandleFunc("/_external-auth-{id}", timelog.TimeLog(authH))

	loginH := http.HandlerFunc(handlers.LoginHandler)
	mux.HandleFunc("/login", timelog.TimeLog(loginH))

	logoutH := http.HandlerFunc(handlers.LogoutHandler)
	mux.HandleFunc("/logout", timelog.TimeLog(logoutH))

	callH := http.HandlerFunc(handlers.CallbackHandler)
	mux.HandleFunc("/auth", timelog.TimeLog(callH))

	healthH := http.HandlerFunc(handlers.HealthcheckHandler)
	mux.HandleFunc("/healthcheck", timelog.TimeLog(healthH))

	if log.GetLevel() == log.DebugLevel {
		path, err := filepath.Abs(staticDir)
		if err != nil {
			log.Errorf("couldn't find static assets at %s", path)
		}
		log.Debugf("serving static files from %s", path)
	}
	// https://golangcode.com/serve-static-assets-using-the-mux-router/
	mux.PathPrefix(staticDir).Handler(http.StripPrefix(staticDir, (http.FileServer(http.Dir("." + staticDir)))))

	if cfg.Cfg.WebApp {
		log.Info("enabling websocket")
		tran.ExplicitInit()
		mux.Handle("/ws", tran.WS)
	}

	// socketio := tran.NewServer()
	// mux.Handle("/socket.io/", cors.AllowAll(socketio))
	// http.Handle("/socket.io/", tran.Server)

	srv := &http.Server{
		Handler: mux,
		Addr:    listen,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		/// logrus has an example of using ErrorLog but it doesn't apply to this MUX implimentation
		// https://github.com/sirupsen/logrus#logger-as-an-iowriter
		// ErrorLog:     log.New(w, "", 0),
	}

	log.Fatal(srv.ListenAndServe())

}
