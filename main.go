package main

// lasso
// git.fs.bnf.net/bnfinet/lasso

import (
	"net/http"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"

	"git.fs.bnf.net/bnfinet/lasso/handlers"
	"git.fs.bnf.net/bnfinet/lasso/pkg/cfg"
	"git.fs.bnf.net/bnfinet/lasso/pkg/timelog"
	tran "git.fs.bnf.net/bnfinet/lasso/pkg/transciever"
)

func main() {
	log.Info("starting lasso")
	mux := http.NewServeMux()

	authH := http.HandlerFunc(handlers.AuthRequestHandler)
	mux.HandleFunc("/authrequest", timelog.TimeLog(authH))

	loginH := http.HandlerFunc(handlers.LoginHandler)
	mux.HandleFunc("/login", timelog.TimeLog(loginH))

	gcallH := http.HandlerFunc(handlers.GCallbackHandler)
	mux.HandleFunc("/auth", timelog.TimeLog(gcallH))

	mux.Handle("/static", http.FileServer(http.Dir("./static")))

	mux.Handle("/ws", tran.WS)

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
	// go func() {
	// 	log.Println(http.ListenAndServe("127.0.0.1:6060", nil))
	// }()

}
