package main

// lasso
// github.com/bnfinet/lasso

import (
	"net/http"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/bnfinet/lasso/handlers"
	"github.com/bnfinet/lasso/pkg/cfg"
	"github.com/bnfinet/lasso/pkg/timelog"
	tran "github.com/bnfinet/lasso/pkg/transciever"
)

func main() {
	log.Info("starting lasso")
	mux := http.NewServeMux()
	// router := mux.NewRouter()
	// router.HandleFunc("/", handlers.IndexHandler)

	authH := http.HandlerFunc(handlers.ValidateRequestHandler)
	mux.HandleFunc("/validate", timelog.TimeLog(authH))
	// mux.HandleFunc("/validate", handlers.ValidateRequestHandler)

	loginH := http.HandlerFunc(handlers.LoginHandler)
	mux.HandleFunc("/login", timelog.TimeLog(loginH))

	logoutH := http.HandlerFunc(handlers.LogoutHandler)
	mux.HandleFunc("/logout", timelog.TimeLog(logoutH))

	callH := http.HandlerFunc(handlers.CallbackHandler)
	mux.HandleFunc("/auth", timelog.TimeLog(callH))

	// router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	mux.Handle("/static", http.FileServer(http.Dir("./static")))

	mux.Handle("/ws", tran.WS)

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
	}

	log.Fatal(srv.ListenAndServe())

}
