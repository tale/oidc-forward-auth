package http_utils

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/tale/oidc-forward-auth/internal/util"
)

// Represents the structure of the authentication cookie.
type AuthCookie struct {
	ID  string `json:"id"`  // ULID or sub
	Exp int64  `json:"exp"` // UNIX timestamp (seconds)
}

// Issues a non server-side auth cookie for the user.
// This is used to identify the user in subsequent requests and skip re-auth.
func IssueAuthCookie(config *util.Config, id string, exp int64) (*http.Cookie, error) {
	log := util.GetLogger()

	cookie := AuthCookie{
		ID:  id,
		Exp: exp,
	}

	data, err := json.Marshal(cookie)
	if err != nil {
		log.Error("Failed to marshal auth cookie: %v", err)
		return nil, err
	}

	s := securecookie.New([]byte(config.CookieSecret), nil)
	encoded, err := s.Encode(config.CookieName, data)
	if err != nil {
		log.Error("Failed to encode auth cookie: %v", err)
		return nil, err
	}

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   config.CookieDomain,
		Secure:   config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(exp, 0),
		HttpOnly: true,
	}, nil
}

// Used to check if we are already authenticated and return early in the
// OIDC forward authentication flow, error means not authenticated.
func ShouldSkipReauth(config *util.Config, r *http.Request) bool {
	log := util.GetLogger()

	cookie, err := r.Cookie(config.CookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return false // No cookie means we are not authenticated
		}

		log.Error("Failed to get auth cookie: %v", err)
		return false
	}

	s := securecookie.New([]byte(config.CookieSecret), nil)
	var data []byte
	err = s.Decode(config.CookieName, cookie.Value, &data)
	if err != nil {
		log.Error("Failed to decode auth cookie: %v", err)
		return false
	}

	var authCookie AuthCookie
	err = json.Unmarshal(data, &authCookie)
	if err != nil {
		log.Error("Failed to unmarshal auth cookie: %v", err)
		return false
	}

	return authCookie.ID != "" && authCookie.Exp > time.Now().Unix()
}
