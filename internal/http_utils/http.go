package http_utils

import (
	"fmt"
	"net/http"

	"github.com/tale/oidc-forward-auth/internal/util"
)

func RegisterHandlers(config *util.Config, oauth2 *OidcClient) {
	http.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(config.CookieName)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Cookie: nil"))
			return
		}

		body := fmt.Sprintf("Cookie: %s", cookie)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	})
}
