package oidc_forward_auth

import (
	"errors"
	"fmt"
	"log"
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
	Debug        bool   // Enable debug logging
	CookieDomain string // Defaults to the root of your auth host subdomain (eg. .example.com)
	CookieName   string // The name of the cookie that stores the session token
	CookieSecure bool   // Set the secure flag on the cookie (are we on HTTPS?)
	CookieExpiry int64  // The expiry time of the cookie in minutes (default 60)
	Port         int    // The port that the forward auth gateway will run on
}

const (
	CookieSecret = "COOKIE_SECRET"
	GatewayURL   = "GATEWAY_URL"
	OidcIssuer   = "OIDC_ISSUER"
	ClientId     = "OIDC_CLIENT_ID"
	ClientSecret = "OIDC_CLIENT_SECRET"

	// Optional
	DebugEnv     = "DEBUG"
	CookieDomain = "COOKIE_DOMAIN"
	CookieName   = "COOKIE_NAME"
	CookieSecure = "COOKIE_SECURE"
	CookieExpiry = "COOKIE_EXPIRY"
	Port         = "PORT"
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
			log.Println(nil, "error getting root domain from %s", gatewayUrl)
			log.Println(nil, "you should probably set %s manually", CookieDomain)
			return nil, ErrInvalidGatewayURL
		}
	}

	cookieName := os.Getenv(CookieName)
	if cookieName == "" {
		cookieName = "_forward_oidc"
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
			log.Println(nil, "error converting %s: %v", CookieExpiry, err)
			return nil, err
		}

		realCookieExpiry = conv
	}

	port := os.Getenv(Port)
	realPort := 4180
	if port != "" {
		conv, err := strconv.Atoi(port)
		if err != nil {
			log.Println(nil, "error converting %s: %v", Port, err)
			return nil, err
		}

		realPort = conv
	}

	return &Config{
		Debug:        debug,
		CookieSecret: cookieSecret,
		GatewayURL:   gatewayUrl,
		OidcIssuer:   oidcIssuer,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		CookieDomain: cookieDomain,
		CookieName:   cookieName,
		CookieSecure: cookieSecure,
		CookieExpiry: realCookieExpiry,
		Port:         realPort,
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

	host, _, err := net.SplitHostPort(url.Host)
	if err != nil {
		log.Error("Error splitting host and port %s: %v", url.Host, err)
		return ""
	}

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return domain
	}

	return "." + strings.Join(parts[len(parts)-2:], ".")
}
