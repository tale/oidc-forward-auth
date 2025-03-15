package main

import (
	"fmt"
	"net/http"
	"os"

	oidc_forward_auth "github.com/tale/oidc-forward-auth/internal"
)

var (
	GitTag    = "dev"
	GitCommit = "unknown"
)

func main() {
	log := oidc_forward_auth.GetLogger()
	log.Info("Starting oidc-forward-auth %s (sha:%s)", GitTag, GitCommit)
	config, err := oidc_forward_auth.LoadConfig()
	if err != nil {
		log.Error("Failed to load config: %v", err)
		os.Exit(1)
	}

	if config.Debug {
		log.SetDebug(true)
	}

	oauth2, err := oidc_forward_auth.NewClient(config)
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
	oidc_forward_auth.RegisterHandlers(config, oauth2)

	port := fmt.Sprintf(":%d", config.Port)
	log.Info("Listening on %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
