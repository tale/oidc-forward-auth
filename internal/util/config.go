package util

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	_ "github.com/joho/godotenv/autoload"
)

type Config struct {
	CookieSecret string // The secret used to encrypt the session cookie
	GatewayURL   string // The URL of the forward auth gateway (eg. https://auth.example.com)
	OidcIssuer   string // The OIDC issuer URL (eg. https://oidc.example.com)
	ClientId     string // The OIDC client ID
	ClientSecret string // The OIDC client secret

	// Optional
	Debug           bool   // Enable debug logging
	CookieDomain    string // Defaults to the root of your auth host subdomain (eg. .example.com)
	CookieName      string // The name of the cookie that stores the session token (default: _forward_oidc)
	StateCookieName string // The name of the cookie that stores the state token (default: _forward_oidc_state)
	CookieSecure    bool   // Set the secure flag on the cookie (are we on HTTPS?)
	CookieExpiry    int64  // The expiry time of the cookie in minutes (default 60)
	Port            int    // The port that the forward auth gateway will run on

	LoginWindow int64 // How long to wait for a user to log in before timing out in minutes (default 2)
	CacheSize   int   // The size of the cache for storing OIDC tokens (default 500)
}

const (
	CookieSecret = "COOKIE_SECRET"
	GatewayURL   = "GATEWAY_URL"
	OidcIssuer   = "OIDC_ISSUER"
	ClientId     = "OIDC_CLIENT_ID"
	ClientSecret = "OIDC_CLIENT_SECRET"

	// Optional
	DebugEnv        = "DEBUG"
	CookieDomain    = "COOKIE_DOMAIN"
	CookieName      = "COOKIE_NAME"
	StateCookieName = "STATE_COOKIE_NAME"
	CookieSecure    = "COOKIE_SECURE"
	CookieExpiry    = "COOKIE_EXPIRY"
	Port            = "PORT"

	LoginWindow = "LOGIN_WINDOW"
	CacheSize   = "CACHE_SIZE"
)

var (
	ErrMissingCookieSecret = errors.New(fmt.Sprintf("missing %s", CookieSecret))
	ErrCookieSecretLength  = errors.New(fmt.Sprintf("%s must be 32 characters", CookieSecret))
	ErrMissingGatewayURL   = errors.New(fmt.Sprintf("missing %s", GatewayURL))
	ErrInvalidGatewayURL   = errors.New(fmt.Sprintf("%s must be a valid URL", GatewayURL))
	ErrMissingOidcIssuer   = errors.New(fmt.Sprintf("missing %s", OidcIssuer))
	ErrMissingClientId     = errors.New(fmt.Sprintf("missing %s", ClientId))
	ErrMissingClientSecret = errors.New(fmt.Sprintf("missing %s", ClientSecret))
)

func LoadConfig() (*Config, error) {
	log := GetLogger()
	debug := os.Getenv(DebugEnv) == "true"

	cookieSecret := os.Getenv(CookieSecret)
	if cookieSecret == "" {
		return nil, ErrMissingCookieSecret
	}

	// Validate cookie secret is 32 chars (generated using openssl rand -hex 16)
	if len(cookieSecret) != 32 {
		return nil, ErrCookieSecretLength
	}

	gatewayUrl := os.Getenv(GatewayURL)
	if gatewayUrl == "" {
		return nil, ErrMissingGatewayURL
	}

	// Validate the gateway URL is a valid URL
	if _, err := url.Parse(gatewayUrl); err != nil {
		return nil, ErrInvalidGatewayURL
	}

	oidcIssuer := os.Getenv(OidcIssuer)
	if oidcIssuer == "" {
		return nil, ErrMissingOidcIssuer
	}

	clientId := os.Getenv(ClientId)
	if clientId == "" {
		return nil, ErrMissingClientId
	}

	clientSecret := os.Getenv(ClientSecret)
	if clientSecret == "" {
		return nil, ErrMissingClientSecret
	}

	cookieDomain := os.Getenv(CookieDomain)
	if cookieDomain == "" {
		cookieDomain = subdomainToRootCookie(gatewayUrl)
		if cookieDomain == "" {
			log.Error("Cannot determine cookie domain from %s", gatewayUrl)
			log.Error("If this persists, please set %s manually", CookieDomain)
			return nil, ErrInvalidGatewayURL
		}
	}

	cookieName := os.Getenv(CookieName)
	if cookieName == "" {
		cookieName = "_forward_oidc"
	}

	stateCookieName := os.Getenv(StateCookieName)
	if stateCookieName == "" {
		stateCookieName = "_forward_oidc_state"
	}

	// Default to secure cookies and require setting to false to disable
	cookieSecure := true
	if os.Getenv(CookieSecure) == "false" {
		cookieSecure = false
	}

	cookieExpiry := os.Getenv(CookieExpiry)
	realCookieExpiry := int64(60)
	if cookieExpiry != "" {
		conv, err := strconv.ParseInt(cookieExpiry, 10, 64)
		if err != nil {
			log.Error("Unable to load a value for %s", CookieExpiry)
			log.Error("Unable to parse %s as an integer: %v", cookieExpiry, err)
			return nil, err
		}

		realCookieExpiry = conv
	}

	port := os.Getenv(Port)
	realPort := 4180
	if port != "" {
		conv, err := strconv.Atoi(port)
		if err != nil {
			log.Error("Unable to load a value for %s", Port)
			log.Error("Unable to parse %s as a port: %v", port, err)
			return nil, err
		}

		realPort = conv
	}

	loginWindow := int64(2) // Default to 2 minutes
	loginWindowEnv := os.Getenv(LoginWindow)
	if loginWindowEnv != "" {
		conv, err := strconv.ParseInt(loginWindowEnv, 10, 64)
		if err != nil {
			log.Error("Unable to load a value for %s", LoginWindow)
			log.Error("Unable to parse %s as an integer: %v", loginWindowEnv, err)
			return nil, err
		}

		loginWindow = conv
	}

	cacheSize := 500 // Default to 500
	cacheSizeEnv := os.Getenv(CacheSize)
	if cacheSizeEnv != "" {
		conv, err := strconv.Atoi(cacheSizeEnv)
		if err != nil {
			log.Error("Unable to load a value for %s", CacheSize)
			log.Error("Unable to parse %s as an integer: %v", cacheSizeEnv, err)
			return nil, err
		}

		cacheSize = conv
	}

	return &Config{
		Debug:           debug,
		CookieSecret:    cookieSecret,
		GatewayURL:      gatewayUrl,
		OidcIssuer:      oidcIssuer,
		ClientId:        clientId,
		ClientSecret:    clientSecret,
		CookieDomain:    cookieDomain,
		CookieName:      cookieName,
		StateCookieName: stateCookieName,
		CookieSecure:    cookieSecure,
		CookieExpiry:    realCookieExpiry,
		Port:            realPort,
		LoginWindow:     loginWindow,
		CacheSize:       cacheSize,
	}, nil
}

func subdomainToRootCookie(domain string) string {
	log := GetLogger()

	// Parse the domain as a URL to get the host
	url, err := url.Parse(domain)
	if err != nil {
		log.Error("Error parsing Gateway URL %s: %v", domain, err)
		return ""
	}

	host := url.Host
	if strings.Contains(url.Host, ":") {
		host, _, err = net.SplitHostPort(url.Host)
		if err != nil {
			log.Error("Error splitting host and port %s: %v", url.Host, err)
			return ""
		}
	}

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return domain
	}

	return "." + strings.Join(parts[len(parts)-2:], ".")
}
