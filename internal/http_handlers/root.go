package http_handlers

import (
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tale/oidc-forward-auth/internal/http_utils"
	"github.com/tale/oidc-forward-auth/internal/util"
)

func HandleRoot(config *util.Config, oauth2 *http_utils.OidcClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := util.GetLogger()
		log.Debug("=============")

		if http_utils.ShouldSkipReauth(config, r) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Already authenticated"))
			return
		}

		reject, err := http_utils.ShouldRejectNewState(config, r)
		if err != nil {
			// Clear the cookie if we have an error, and we can proceed
			// with the normal authentication flow
			http.SetCookie(w, http_utils.ClearStateCookie(config))
		} else if reject {
			// Here we don't have an error, but we have a reject condition
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Login is already in progress"))
			return
		}

		url, ok := http_utils.DetermineRedirectURI(r)
		if !ok {
			// There is a case where auth just outright failed, and in this
			// case lets just redirect back to the original URL. Traefik
			// can handle this however it sees fit.

			log.Error("Failed to determine redirect URI for %s", r.RemoteAddr)
			http.Error(w, "Missing params to determine redirect URI", http.StatusBadRequest)
			return
		}

		log.Debug("Storing URL %s for %s", url.String(), r.RemoteAddr)
		stateCookie, stateID, nonce, err := http_utils.IssueStateCookie(config, url.String())
		if err != nil {
			http.Error(w, "Failed to issue state cookie", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, stateCookie)
		authUrl := oauth2.AuthCodeURL(stateID.String(), oidc.Nonce(nonce))
		http.Redirect(w, r, authUrl, http.StatusFound)
	}
}
