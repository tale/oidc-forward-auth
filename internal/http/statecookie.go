package http

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/oklog/ulid/v2"
	"github.com/tale/oidc-forward-auth/internal/store"
	"github.com/tale/oidc-forward-auth/internal/util"
)

// Checks if we have an in-progress state cookie and rejects the request if so.
// This is used to prevent different URLs overriding each other, breaking auth.
func shouldRejectNewState(config *util.Config, r *http.Request) bool {
	log := util.GetLogger()

	cookie, err := r.Cookie(config.CookieName)
	if err != nil {
		// This means we don't have a cookie
		log.Debug("Request from %s has no cookie", r.RemoteAddr)
		return false
	}

	var value string
	s := securecookie.New([]byte(config.CookieSecret), nil)
	err = s.Decode(config.CookieName, cookie.Value, &value)
	if err != nil {
		log.Error("Unable to decode cookie from %s: %v", r.RemoteAddr, err)
		return false
	}

	log.Debug("Decoded cookie from %s: %s", r.RemoteAddr, value)
	stateID, err := ulid.Parse(value)
	if err != nil {
		log.Error("Unable to parse ULID in cookie from %s: %v", r.RemoteAddr, err)
		return false
	}

	// Check if the state ID is in-progress
	stateKey, err := store.GetState(stateID)
	if err != nil {
		log.Debug("Failed to get state from store for %s: %v", r.RemoteAddr, err)
		return false
	}

	if stateKey == nil {
		// No state found, so we can proceed
		// This means the state is either completed or expired
		log.Debug("Request from %s has no in-progress state cookie, proceeding", r.RemoteAddr)
		return false
	}

	if stateKey.AuthInProgress {
		// We have a state cookie, so we reject the request
		log.Debug("Request from %s has in-progress state cookie, rejecting", r.RemoteAddr)
		return true
	}

	return false
}

// Issues an in-progress state cookie that contains a nonce and a redirect URL.
// This will also set the state in the store, so that we can later retrieve it.
func issueStateCookie(config *util.Config, redirectURL string) (*http.Cookie, *ulid.ULID, string, error) {
	log := util.GetLogger()

	log.Debug("Issuing state cookie for redirect URL: %s", redirectURL)
	nonce, err := GenerateNonce()
	if err != nil {
		log.Error("Failed to generate nonce for state cookie: %v", err)
		return nil, nil, "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	id, err := store.SetState(nonce, redirectURL)
	if err != nil {
		log.Error("Failed to set state in store: %v", err)
		return nil, nil, "", fmt.Errorf("failed to set state: %w", err)
	}

	s := securecookie.New([]byte(config.CookieSecret), nil)
	encoded, err := s.Encode(config.CookieName, id.String())
	if err != nil {
		store.DeleteState(id) // We can ignore the error here (probably?)
		log.Error("Failed to encode state cookie: %v", err)
		return nil, nil, "", fmt.Errorf("failed to encode state cookie: %w", err)
	}

	expires := time.Now().Add(time.Duration(config.LoginWindow) * time.Minute)
	return &http.Cookie{
		Name:     config.CookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   config.CookieDomain,
		Secure:   config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		HttpOnly: true,
	}, id, nonce, nil
}

// Decodes the state cookie and retrieves the state ID and key from the store.
func decodeStateCookie(config *util.Config, cookie *http.Cookie) (*ulid.ULID, *store.StateKey, error) {
	log := util.GetLogger()

	var value string
	s := securecookie.New([]byte(config.CookieSecret), nil)
	err := s.Decode(config.CookieName, cookie.Value, &value)
	if err != nil {
		log.Error("Unable to decode state cookie: %v", err)
		return nil, nil, fmt.Errorf("failed to decode state cookie: %w", err)
	}

	stateID, err := ulid.Parse(value)
	if err != nil {
		log.Error("Unable to parse ULID in state cookie: %v", err)
		return nil, nil, fmt.Errorf("failed to parse state ID: %w", err)
	}

	stateKey, err := store.GetState(stateID)
	if err != nil {
		log.Error("Failed to get state from store: %v", err)
		return nil, nil, fmt.Errorf("failed to get state from store: %w", err)
	}

	return &stateID, stateKey, nil
}

func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
