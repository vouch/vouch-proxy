package handlers

import (
	"fmt"
	"net/http"
)

// HealthcheckHandler /healthcheck
// just returns 200 '{ "ok": true }'
func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if _, err := fmt.Fprintf(w, "{ \"ok\": true }"); err != nil {
		log.Error(err)
	}
}
