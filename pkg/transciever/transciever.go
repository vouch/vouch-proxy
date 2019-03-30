package transciever

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

// WSHandler implements the Handler Interface
type WSHandler struct{}

// WS to handle
var WS = &WSHandler{}

type HubHolder struct {
	Hub *Hub
}

var hh = &HubHolder{
	Hub: newHub(),
}

// ExplicitInit only run init() if we're configured for such
func ExplicitInit() {
	log.Debug("hub %v", hh.Hub)
	go hh.Hub.run()
}

func (WS WSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Info("ws endpoint")
	// jwt := handlers.FindJWT(r)
	// if jwt == "" {
	// 	http.Error(w, "your mother", http.StatusUnauthorized)
	// 	return
	// }
	// claims, err := handlers.ClaimsFromJWT(jwt)
	// // lookup the User
	// user := structs.User{}
	// err = model.User([]byte(claims.Email), &user)
	// if err != nil {
	// 	// no email in jwt
	// 	http.Error(w, "your mother", http.StatusUnauthorized)
	// 	return
	// }
	log.Infof("hub %v", hh.Hub)
	serveWs(hh.Hub, w, r)
}
