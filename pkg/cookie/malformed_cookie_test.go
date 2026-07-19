package cookie

import (
	"net/http"
	"testing"

	"github.com/vouch/vouch-proxy/pkg/cfg"
)

func TestMalformedMultipartCookieRejected(t *testing.T) {
	cfg.Cfg.Cookie.Name = "vouch"
	for _, ck := range []string{"vouch_1=x", "vouch_0of1=x", "vouch_-1of2=x", "vouch_2of1=x"} {
		r := &http.Request{Header: map[string][]string{"Cookie": {ck}}}
		if _, err := Cookie(r); err == nil {
			t.Errorf("malformed cookie %q should return an error, got nil", ck)
		}
	}
	// a valid multipart cookie still reassembles
	r := &http.Request{Header: map[string][]string{"Cookie": {"vouch_1of2=foo", "vouch_2of2=bar"}}}
	v, err := Cookie(r)
	if err != nil || v != "foobar" {
		t.Errorf("valid multipart cookie broke: got %q err=%v", v, err)
	}
}
