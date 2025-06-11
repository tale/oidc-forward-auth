package main

import (
	"fmt"
	"net/http"
	"os"

	h "github.com/tale/oidc-forward-auth/internal/http"
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

	oauth2, err := h.NewClient(config)
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

	err = store.InitStateStore(500)
	if err != nil {
		log.Error("Failed to initialize state store: %v", err)
		os.Exit(1)
	}

	h.RegisterHandlers(config, oauth2)

	port := fmt.Sprintf(":%d", config.Port)
	log.Info("Listening on %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
