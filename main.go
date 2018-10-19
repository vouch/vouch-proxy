package main

// lasso
// github.com/LassoProject/lasso

import (
	"net/http"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/LassoProject/lasso/handlers"
	"github.com/LassoProject/lasso/pkg/cfg"
	"github.com/LassoProject/lasso/pkg/timelog"
	tran "github.com/LassoProject/lasso/pkg/transciever"
)

func main() {
	log.Info("starting lasso")
	mux := http.NewServeMux()

	authH := http.HandlerFunc(handlers.ValidateRequestHandler)
	mux.HandleFunc("/validate", timelog.TimeLog(authH))

	loginH := http.HandlerFunc(handlers.LoginHandler)
	mux.HandleFunc("/login", timelog.TimeLog(loginH))

	logoutH := http.HandlerFunc(handlers.LogoutHandler)
	mux.HandleFunc("/logout", timelog.TimeLog(logoutH))

	callH := http.HandlerFunc(handlers.CallbackHandler)
	mux.HandleFunc("/auth", timelog.TimeLog(callH))

	// serve static files from /static
	mux.Handle("/static", http.FileServer(http.Dir("./static")))

	if cfg.Cfg.WebApp {
		log.Info("enabling websocket")
		tran.ExplicitInit()
		mux.Handle("/ws", tran.WS)
	}

	// socketio := tran.NewServer()
	// mux.Handle("/socket.io/", cors.AllowAll(socketio))
	// http.Handle("/socket.io/", tran.Server)

	var listen = cfg.Cfg.Listen + ":" + strconv.Itoa(cfg.Cfg.Port)
	log.Infof("running lasso on %s", listen)

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
