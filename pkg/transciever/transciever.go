package transciever

import (
	"net/http"

	"git.fs.bnf.net/bnfinet/lasso/handlers"
	"git.fs.bnf.net/bnfinet/lasso/pkg/model"
	"git.fs.bnf.net/bnfinet/lasso/pkg/structs"

	log "github.com/Sirupsen/logrus"
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

// NewHub
func init() {
	log.Info("hub %v", hh.Hub)
	go hh.Hub.run()
}

func (WS WSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Infof("ws endpoint")
	email, err := handlers.EmailFromCookieJWT(w, r)
	// lookup the User
	user := structs.User{}
	err = model.User([]byte(email), &user)
	if err != nil {
		// no email in jwt
		http.Error(w, "your mother", http.StatusUnauthorized)
		return
	}
	log.Info("hub %v", hh.Hub)
	serveWs(hh.Hub, w, r)
}
