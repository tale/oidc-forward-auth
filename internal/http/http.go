package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log := util.GetLogger()

		if shouldSkipReauth(config, r) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Already authenticated"))
			return
		}

		if shouldRejectNewState(config, r) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Login is already in progress"))
			return
		}

		// To construct the "true" redirect URI we need the following:
		// - X-Forwarded-Proto
		// - X-Forwarded-Host
		// - X-Forwarded-Uri
		// - X-Forwarded-Port (Special, we check if X-Forwarded-Host already contains the port)
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Missing X-Forwarded-Host"))
			return
		}

		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			// Assume HTTP (This behavior could be bad)
			proto = "http"
		}

		// Handle default ports first
		port := r.Header.Get("X-Forwarded-Port")
		if port == "" {
			if proto == "http" {
				port = "80"
			} else {
				port = "443"
			}
		}

		// Check if the host already contains the port by trying to split
		_, _, err := net.SplitHostPort(host)
		if err != nil {
			// If we get an error, we need to append the port
			host = net.JoinHostPort(host, port)
		}

		uri := r.Header.Get("X-Forwarded-Uri")
		if uri == "" {
			uri = "/"
		}

		url := &url.URL{
			Scheme: proto,
			Host:   host,
			Path:   uri,
		}

		log.Debug("Storing URL %s for %s", url.String(), r.RemoteAddr)
		stateCookie, stateID, nonce, err := issueStateCookie(config, url.String())
		if err != nil {
			http.Error(w, "Failed to issue state cookie", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, stateCookie)

		// Check for login hints
		authUrl := oauth2.AuthCodeURL(stateID.String(), oidc.Nonce(nonce))
		http.Redirect(w, r, authUrl, http.StatusFound)
	})

	http.HandleFunc("/oidc", func(w http.ResponseWriter, r *http.Request) {
		log := util.GetLogger()

		cookie, err := r.Cookie(config.CookieName)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Missing cookie"))
			return
		}

		stateID, stateKey, err := decodeStateCookie(config, cookie)
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

		idToken, err := oauth2.verifyCode(ctx, code, stateKey.Nonce)
		if err != nil {
			log.Error("Failed to verify code: %v", err)
			http.Error(w, "Failed to verify code", http.StatusInternalServerError)
			return
		}

		// Make an expiry using the config (CookieExpiry is in minutes)
		exp := time.Now().Add(time.Duration(config.CookieExpiry) * time.Minute)
		cookie, err = issueAuthCookie(config, idToken.Subject, exp.Unix())
		if err != nil {
			log.Error("Failed to issue cookie: %v", err)
			http.Error(w, "Failed to issue cookie", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, cookie)
		log.Debug("Redirecting %s to %s", r.RemoteAddr, stateKey.RedirectURL)
		http.Redirect(w, r, stateKey.RedirectURL, http.StatusFound)
	})

}
