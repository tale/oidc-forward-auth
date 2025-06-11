package http_handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/tale/oidc-forward-auth/internal/http_utils"
	"github.com/tale/oidc-forward-auth/internal/util"
)

func HandleOidcCallback(config *util.Config, oauth2 *http_utils.OidcClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := util.GetLogger()

		cookie, err := r.Cookie(config.StateCookieName)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Missing state cookie"))
			return
		}

		stateID, stateKey, err := http_utils.DecodeStateCookie(config, cookie)
		if err != nil {
			log.Error("Unable to decode state cookie from %s: %v", r.RemoteAddr, err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Failed to decode state cookie"))
			return
		}

		state := r.URL.Query().Get("state")
		if state != (*stateID).String() {
			log.Debug("%s: Invalid State, expected %s, got %s", r.RemoteAddr, (*stateID).String(), state)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid state"))
			return
		}

		// We need the id_token to verify the nonce
		code := r.URL.Query().Get("code")
		ctx := context.Background()

		idToken, err := oauth2.VerifyCode(ctx, code, stateKey.Nonce)
		if err != nil {
			log.Error("Failed to verify code: %v", err)
			http.Error(w, "Failed to verify code", http.StatusInternalServerError)
			return
		}

		// Make an expiry using the config (CookieExpiry is in minutes)
		exp := time.Now().Add(time.Duration(config.CookieExpiry) * time.Minute)
		cookie, err = http_utils.IssueAuthCookie(config, idToken.Subject, exp.Unix())
		if err != nil {
			log.Error("Failed to issue cookie: %v", err)
			http.Error(w, "Failed to issue cookie", http.StatusInternalServerError)
			return
		}

		// We need to also clear the state cookie
		http.SetCookie(w, cookie)
		http.SetCookie(w, http_utils.ClearStateCookie(config))

		log.Debug("Redirecting %s to %s", r.RemoteAddr, stateKey.RedirectURL)
		http.Redirect(w, r, stateKey.RedirectURL, http.StatusFound)
	}
}
