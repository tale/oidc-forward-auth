package main

import (
	"fmt"
	"log"
	"net/http"

	oidc_forward_auth "github.com/tale/oidc-forward-auth/internal"
)

var (
	GitTag    = "dev"
	GitCommit = "unknown"
)

func main() {
	log.Printf("Starting oidc-forward-auth %s (%s)", GitTag, GitCommit)
	config, err := oidc_forward_auth.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	oauth2, err := oidc_forward_auth.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create OAuth2 config: %v", err)
	}

	log.Println("Loading with the following config values:")
	log.Println("Gateway URL:", config.GatewayURL)
	log.Println("Cookie Domain:", config.CookieDomain)
	log.Println("Issuer:", config.OidcIssuer)
	log.Println("Client ID:", config.ClientId)
	log.Println("Redirect URL:", oauth2.RedirectURL)
	oidc_forward_auth.RegisterHandlers(config, oauth2)

	port := fmt.Sprintf(":%d", config.Port)
	log.Println("Listening on", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
