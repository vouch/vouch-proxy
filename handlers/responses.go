package handlers

import (
	"fmt"
	"net/http"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
)

func renderIndex(w http.ResponseWriter, msg string) {
	if err := indexTemplate.Execute(w, &Index{Msg: msg, TestURLs: cfg.Cfg.TestURLs, Testing: cfg.Cfg.Testing}); err != nil {
		log.Error(err)
	}
}
func ok200(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("200 OK\n"))
	if err != nil {
		log.Error(err)
	}
}

func redirect302(w http.ResponseWriter, r *http.Request, rURL string) {
	if cfg.Cfg.Testing {
		cfg.Cfg.TestURLs = append(cfg.Cfg.TestURLs, rURL)
		renderIndex(w, "302 redirect to: "+rURL)
		return
	}
	http.Redirect(w, r, rURL, http.StatusFound)
}

// 400 Bad Request
// returned when the requesed url param for /login or /logout is bd
func error400(w http.ResponseWriter, r *http.Request, e error) {
	log.Error(e)
	cookie.ClearCookie(w, r)
	w.Header().Set("X-Vouch-Error", e.Error())
	http.Error(w, e.Error(), http.StatusUnauthorized)
}

// the standard error
// this is captured by nginx, which converts the 401 into 302 to the login page
func error401(w http.ResponseWriter, r *http.Request, e error) {
	log.Error(e)
	cookie.ClearCookie(w, r)
	w.Header().Set("X-Vouch-Error", e.Error())
	http.Error(w, e.Error(), http.StatusUnauthorized)
}

func error401na(w http.ResponseWriter, r *http.Request) {
	error401(w, r, fmt.Errorf("not authorized"))
}
