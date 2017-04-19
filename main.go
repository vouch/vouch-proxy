package main

// lasso
// git.fs.bnf.net/bnfinet/lasso

// TODO
//  * replace gin sessions with pulling from storage

import (
	"net/http"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"

	"git.fs.bnf.net/bnfinet/lasso/handlers"
	"git.fs.bnf.net/bnfinet/lasso/pkg/cfg"
	"git.fs.bnf.net/bnfinet/lasso/pkg/timelog"
	// "github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
)

func main() {
	log.Info("starting lasso")
	if cfg.Cfg.LogLevel == "debug" {
		log.SetLevel(log.DebugLevel)
		log.Debug("logLevel set to debug")
		// gin.SetMode(gin.DebugMode)
	}

	router := mux.NewRouter()

	// router.HandleFunc("/", handlers.IndexHandler)

	authH := http.HandlerFunc(handlers.AuthRequestHandler)
	router.HandleFunc("/authrequest", timelog.TimeLog(authH))

	loginH := http.HandlerFunc(handlers.LoginHandler)
	router.HandleFunc("/login", timelog.TimeLog(loginH))

	gcallH := http.HandlerFunc(handlers.GCallbackHandler)
	router.HandleFunc("/auth", timelog.TimeLog(gcallH))

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	// authorized := router.Group("/battle")
	// authorized.Use(middleware.AuthorizeRequest())
	// {
	// 	authorized.GET("/field", handlers.FieldHandler)
	// }
	var listen = cfg.Cfg.Listen + ":" + strconv.Itoa(cfg.Cfg.Port)
	log.Infof("running lasso on %s", listen)

	// router.Run(listen)

	srv := &http.Server{
		Handler: router,
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
