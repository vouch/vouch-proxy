package indieauth

import (
	"bytes"
	"encoding/json"
	"github.com/vouch/vouch-proxy/handlers/common"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/structs"
	"io/ioutil"
	"mime/multipart"
	"net/http"
)

var (
	log = cfg.Cfg.Logger
)

func GetUserInfoFromIndieAuth(r *http.Request, user *structs.User, customClaims *structs.CustomClaims) (rerr error) {

	code := r.URL.Query().Get("code")
	log.Errorf("ptoken.AccessToken: %s", code)
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	// v.Set("code", code)
	fw, err := w.CreateFormField("code")
	if err != nil {
		return err
	}
	if _, err = fw.Write([]byte(code)); err != nil {
		return err
	}
	// v.Set("redirect_uri", cfg.GenOAuth.RedirectURL)
	if fw, err = w.CreateFormField("redirect_uri"); err != nil {
		return err
	}
	if _, err = fw.Write([]byte(cfg.GenOAuth.RedirectURL)); err != nil {
		return err
	}
	// v.Set("client_id", cfg.GenOAuth.ClientID)
	if fw, err = w.CreateFormField("client_id"); err != nil {
		return err
	}
	if _, err = fw.Write([]byte(cfg.GenOAuth.ClientID)); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		log.Error("error closing writer.")
	}

	req, err := http.NewRequest("POST", cfg.GenOAuth.AuthURL, &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	// v := url.Values{}
	// userinfo, err := client.PostForm(cfg.GenOAuth.UserInfoURL, v)

	client := &http.Client{}
	userinfo, err := client.Do(req)

	if err != nil {
		// http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer func() {
		if err := userinfo.Body.Close(); err != nil {
			rerr = err
		}
	}()

	data, _ := ioutil.ReadAll(userinfo.Body)
	log.Infof("indieauth userinfo body: %s", string(data))
	if err = common.MapClaims(data, customClaims); err != nil {
		log.Error(err)
		return err
	}
	iaUser := structs.IndieAuthUser{}
	if err = json.Unmarshal(data, &iaUser); err != nil {
		log.Error(err)
		return err
	}
	iaUser.PrepareUserData()
	user.Username = iaUser.Username
	log.Debug(user)
	return nil
}
