package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	oidc_forward_auth "github.com/tale/oidc-forward-auth/internal"
	"golang.org/x/oauth2"
)

func main() {
	config, err := oidc_forward_auth.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	redirectURL := fmt.Sprintf("http://%s/oidc", config.AuthHost)
	log.Println("Loading with the following config values:")
	log.Println("Auth Host:", config.AuthHost)
	log.Println("Cookie Domain:", config.CookieDomain)
	log.Println("Issuer:", config.OidcIssuer)
	log.Println("Client ID:", config.ClientId)

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.OidcIssuer)
	if err != nil {
		// handle error
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		RedirectURL:  redirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
		// Write Cookie if available
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

	// Make an http server to echo the headers and then return 200
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		valid, cookie := oidc_forward_auth.CheckCookieAuth(config, r)
		if valid {
			if cookie != nil {
				http.SetCookie(w, cookie)
			}

			w.WriteHeader(http.StatusOK)
			return
		}

		// To construct the "true" redirect URI we need the following:
		// - X-Forwarded-Proto
		// - X-Forwarded-Host
		// - X-Forwarded-Uri
		// - X-Forwarded-Port (Special, we check if X-Forwarded-Host already contains the port)
		proto := r.Header.Get("X-Forwarded-Proto")
		host := r.Header.Get("X-Forwarded-Host")
		uri := r.Header.Get("X-Forwarded-Uri")
		port := r.Header.Get("X-Forwarded-Port")

		// Split the host at : since hosts cannot legally contain colons
		// If the host contains a colon, it means the port is already included
		hostParts := strings.Split(host, ":")
		if len(hostParts) > 1 {
			host = hostParts[0]
		}

		url := url.URL{
			Scheme: proto,
			Host:   fmt.Sprintf("%s:%s", host, port),
			Path:   uri,
		}

		// Base64 the URL and use it as the state + TODO Randomize the state
		state := base64.URLEncoding.EncodeToString([]byte(url.String()))
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/oidc", func(w http.ResponseWriter, r *http.Request) {
		// Verify the state
		state := r.URL.Query().Get("state")
		decodedState, err := base64.URLEncoding.DecodeString(state)
		if err != nil {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		url := string(decodedState)

		log.Println("URL:", url)
		cookie, err := oidc_forward_auth.IssueCookie(config, "hello")
		if err != nil {
			// Log here as an error, but redirect back so they can try again
			log.Printf("Failed to issue cookie: %v", err)
		}

		http.SetCookie(w, cookie)
		log.Println("Set cookie:", cookie)
		http.Redirect(w, r, url, http.StatusFound)
	})

	// Start the server
	log.Println("Listening on :4180")
	log.Fatal(http.ListenAndServe(":4180", nil))
}
