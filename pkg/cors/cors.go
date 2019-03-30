package cors

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

// AllowAll is middle ware to set Access-Control-Allow-Origin: *
func AllowAll(nextHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		log.Debugf("setting Access-Control-Allow-Origin header to %s", origin)
		nextHandler.ServeHTTP(w, r)
	}
}
