package oidc_forward_auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

type CookieClaims struct {
	// This is NOT the OIDC expiry, but the cookie expiry
	// We employ rolling cookies, so this expiry will get extended
	// If the user makes a request within 1/4 of the expiry time (default: 1h)
	Expiry  int64  `json:"exp"`
	Subject string `json:"sub"`
}

func CheckCookieAuth(config *Config, r *http.Request) (bool, *http.Cookie) {
	cookie, err := r.Cookie(config.CookieName)
	if err != nil {
		return false, nil
	}

	var value string
	s := securecookie.New([]byte(config.CookieSecret), nil)
	err = s.Decode(config.CookieName, cookie.Value, &value)
	if err != nil {
		return false, nil
	}

	// Check if the cookie is expired
	claims := &CookieClaims{}
	err = json.Unmarshal([]byte(value), claims)
	if err != nil {
		return false, nil
	}

	now := time.Now().Unix()
	if now > claims.Expiry {
		// Expired cookie
		return false, nil
	}

	// Check if we are within 1/4 of the expiry time and roll the cookie
	threshold := claims.Expiry - (int64(config.CookieExpiry) / 4)
	if now > threshold {
		newExpiry := now + int64(config.CookieExpiry)
		claims.Expiry = newExpiry

		// If we can't marshal the claims, we can't issue a new cookie
		// BUT we don't want to fail the request, so we just return true
		// and the cookie will attempt a re-issue on the next request
		newValue, err := json.Marshal(claims)
		if err != nil {
			return true, nil
		}

		// Same as above, if we can't encode the cookie, we can't issue a new one
		// But we don't want to fail the request, so we just return true
		cookie, err = IssueCookie(config, string(newValue))
		if err != nil {
			return true, nil
		}

		return true, cookie
	}

	// Validated this is a cookie signed by us
	return true, nil
}

func IssueCookie(config *Config, value string) (*http.Cookie, error) {
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
