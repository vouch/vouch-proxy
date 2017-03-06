package main

// lasso
// git.fs.bnf.net/bnfinet/lasso

// TODO
//  * replace gin sessions with pulling from storage

import (
	log "github.com/Sirupsen/logrus"

	"git.fs.bnf.net/bnfinet/lasso/handlers"
	"git.fs.bnf.net/bnfinet/lasso/middleware"
	"github.com/gin-gonic/gin"
)

func main() {
	log.Info("starting lasso")
	router := gin.Default()
	router.Use(gin.Logger())
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
	router.Run("0.0.0.0:9090")

	// go func() {
	// 	log.Println(http.ListenAndServe("127.0.0.1:6060", nil))
	// }()

}
