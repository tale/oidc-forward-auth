package http_utils

import (
	"context"
	"fmt"
	"net/url"
	"path"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tale/oidc-forward-auth/internal/util"
	"golang.org/x/oauth2"
)

type OidcClient struct {
	*oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewClient(config *util.Config) (*OidcClient, error) {
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

func (oc *OidcClient) VerifyCode(ctx context.Context, code, nonce string) (*oidc.IDToken, error) {
	token, err := oc.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	tok, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token field in oauth2 token")
	}

	idToken, err := oc.verifier.Verify(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token: %w", err)
	}

	if nonce != idToken.Nonce {
		return nil, fmt.Errorf("nonce mismatch: expected %s, got %s", nonce, idToken.Nonce)
	}

	return idToken, nil
}

func (oc *OidcClient) NoPrompt() oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("prompt", "none")
}

func (oc *OidcClient) WithHint(email string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("login_hint", email)
}
