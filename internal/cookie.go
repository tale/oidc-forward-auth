package oidc_forward_auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
)

type CookieClaims struct {
	// This is NOT the OIDC expiry, but the cookie expiry
	// We employ rolling cookies, so this expiry will get extended
	// If the user makes a request within 1/4 of the expiry time (default: 1h)
	Expiry int64 `json:"exp"`

	// Flow variables
	Nonce string `json:"nonce"`
	State string `json:"state"`
}

func CheckCookieAuth(config *Config, r *http.Request) (bool, *http.Cookie) {
	cookie, err := r.Cookie(config.CookieName)
	if err != nil {
		log.Printf("Failed to get cookie: %v", err)
		return false, nil
	}

	var value []byte
	s := securecookie.New([]byte(config.CookieSecret), nil)
	err = s.Decode(config.CookieName, cookie.Value, &value)
	if err != nil {
		log.Printf("Failed to decode cookie: %v", err)
		return false, nil
	}

	// Check if the cookie is expired
	claims := &CookieClaims{}
	err = json.Unmarshal(value, claims)
	if err != nil {
		log.Printf("Failed to unmarshal cookie: %v", err)
		return false, nil
	}

	now := time.Now().Unix()
	if now > claims.Expiry {
		// Expired cookie
		log.Printf("Cookie expired: %v", claims.Expiry)
		return false, nil
	}

	// Check if we are within 1/4 of the expiry time and roll the cookie
	threshold := claims.Expiry - (int64(config.CookieExpiry) / 4)
	if now > threshold {
		newExpiry := now + int64(config.CookieExpiry)
		claims.Expiry = newExpiry

		// If we can't encode the cookie, we can't issue a new one
		// But we don't want to fail the request, so we just return true
		// This won't renew the cookie, but auth flow will still be successful
		cookie, err = IssueCookie(config, claims)
		if err != nil {
			log.Printf("Failed to issue cookie: %v", err)
			return true, nil
		}

		log.Printf("Rolled cookie expiry to: %v", newExpiry)
		return true, cookie
	}

	// Validated this is a cookie signed by us
	return true, nil
}

func IssueCookie(config *Config, claims *CookieClaims) (*http.Cookie, error) {
	value, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	s := securecookie.New([]byte(config.CookieSecret), nil)
	encoded, err := s.Encode(config.CookieName, value)
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   config.CookieDomain,
		Secure:   config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	}, nil
}

func DecodeCookie(config *Config, cookie *http.Cookie) (*CookieClaims, error) {
	var value []byte
	s := securecookie.New([]byte(config.CookieSecret), nil)
	err := s.Decode(config.CookieName, cookie.Value, &value)
	if err != nil {
		return nil, err
	}

	claims := &CookieClaims{}
	err = json.Unmarshal(value, claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func GenerateState(url string) (string, error) {
	stateRand := make([]byte, 16)
	_, err := rand.Read(stateRand)
	if err != nil {
		return "", err
	}

	// Concat with a dash to separate the URL from the random bytes
	base64url := base64.URLEncoding.Strict().EncodeToString([]byte(url))
	state := base64url + "-" + base64.URLEncoding.EncodeToString(stateRand)
	return state, nil
}

func GetURLFromState(state string) (string, error) {
	// Split the state into the URL and the random bytes
	split := strings.Split(state, "-")
	if len(split) != 2 {
		return "", errors.New("Invalid state")
	}

	url, err := base64.URLEncoding.Strict().DecodeString(split[0])
	if err != nil {
		return "", err
	}

	return string(url), nil
}

func GenerateNonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(nonce), nil
}
