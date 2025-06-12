package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/tale/oidc-forward-auth/internal/http_handlers"
	"github.com/tale/oidc-forward-auth/internal/http_utils"
	"github.com/tale/oidc-forward-auth/internal/store"
	"github.com/tale/oidc-forward-auth/internal/util"
)

var (
	GitTag    = "dev"
	GitCommit = "unknown"
)

func main() {
	log := util.GetLogger()
	log.Info("Starting oidc-forward-auth %s (sha:%s)", GitTag, GitCommit)
	config, err := util.LoadConfig()
	if err != nil {
		log.Error("Failed to load config: %v", err)
		os.Exit(1)
	}

	if config.Debug {
		log.SetDebug(true)
	}

	oauth2, err := http_utils.NewClient(config)
	if err != nil {
		log.Error("Failed to create OAuth2 config: %v", err)
		os.Exit(1)
	}

	log.Info("Loading with the following config values:")
	log.Info("Gateway URL: %s", config.GatewayURL)
	log.Info("Cookie Domain: %s", config.CookieDomain)
	log.Info("Issuer: %s", config.OidcIssuer)
	log.Info("Client ID: %s", config.ClientId)
	log.Info("Redirect URL: %s", oauth2.RedirectURL)
	log.Info("=========================")
	log.Info("Cookie Name: %s", config.CookieName)
	log.Info("State Cookie Name: %s", config.StateCookieName)

	err = store.InitStateStore(config.CacheSize)
	if err != nil {
		log.Error("Failed to initialize state store: %v", err)
		os.Exit(1)
	}

	http.HandleFunc("/", http_handlers.HandleRoot(config, oauth2))
	http.HandleFunc("/oidc", http_handlers.HandleOidcCallback(config, oauth2))
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

	port := fmt.Sprintf(":%d", config.Port)
	log.Info("Listening on %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
