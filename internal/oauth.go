package oidc_forward_auth

import (
	"context"
	"net/url"
	"path"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OidcClient struct {
	*oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewClient(config *Config) (*OidcClient, error) {
	// Redirect URL is made through our config
	url, err := url.Parse(config.GatewayURL)
	if err != nil {
		return nil, err
	}

	// Append /oidc to the Gateway URL
	url.Path = path.Join(url.Path, "oidc")

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.OidcIssuer)
	if err != nil {
		return nil, err
	}

	oauth2 := &oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		RedirectURL:  url.String(),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcConfig := &oidc.Config{
		ClientID: oauth2.ClientID,
	}

	verifier := provider.Verifier(oidcConfig)
	return &OidcClient{oauth2, verifier}, nil
}
