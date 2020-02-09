package homeassistant

import (
	"github.com/vouch/vouch-proxy/pkg/structs"
	"net/http"
)

// More info: https://developers.home-assistant.io/docs/en/auth_api.html
func GetUserInfoFromHomeAssistant(r *http.Request, user *structs.User, customClaims *structs.CustomClaims) (rerr error) {
	// Home assistant does not provide an API to query username, so we statically set it to "homeassistant"
	user.Username = "homeassistant"
	return nil
}
