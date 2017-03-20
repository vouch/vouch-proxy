package main

// lasso
// git.fs.bnf.net/bnfinet/lasso

// TODO
//  * replace gin sessions with pulling from storage

import (
	"strconv"

	log "github.com/Sirupsen/logrus"

	"git.fs.bnf.net/bnfinet/lasso/handlers"
	"git.fs.bnf.net/bnfinet/lasso/middleware"
	"git.fs.bnf.net/bnfinet/lasso/pkg/cfg"
	"github.com/gin-gonic/gin"
)

func main() {
	log.Info("starting lasso")
	if cfg.Cfg.LogLevel == "debug" {
		log.SetLevel(log.DebugLevel)
		log.Debug("logLevel set to debug")
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	if cfg.Cfg.LogLevel == "debug" {
		router.Use(gin.Logger())
	}
	router.Static("/css", "./static/css")
	router.Static("/img", "./static/img")
	router.LoadHTMLGlob("templates/*")

	router.GET("/", handlers.IndexHandler)
	router.GET("/authrequest", handlers.AuthRequestHandler)
	router.GET("/login", handlers.LoginHandler)
	router.GET("/auth", handlers.GCallbackHandler)

	authorized := router.Group("/battle")
	authorized.Use(middleware.AuthorizeRequest())
	{
		authorized.GET("/field", handlers.FieldHandler)
	}
	var listen = cfg.Cfg.Listen + ":" + strconv.Itoa(cfg.Cfg.Port)
	log.Infof("running lasso on %s", listen)
	router.Run(listen)
	// go func() {
	// 	log.Println(http.ListenAndServe("127.0.0.1:6060", nil))
	// }()

}
