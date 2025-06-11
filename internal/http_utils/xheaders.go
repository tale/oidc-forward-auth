package http_utils

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
)

// Represents all the forwarded headers
type XHeaders struct {
	Host  string // X-Forwarded-Host
	Proto string // X-Forwarded-Proto
	Port  int    // X-Forwarded-Port
	Uri   string // X-Forwarded-Uri
}

// Constructs the redirect URI based on the X-Forwarded headers.
// Does some smart optimizations, for example, if we are in HTTPS and
// the port is 443, we don't include the port in the URL.
func DetermineRedirectURI(r *http.Request) (*url.URL, bool) {
	xHeaders, ok := getXHeaders(r)
	if !ok {
		return nil, false
	}

	// Construct the URL based on the X-Forwarded headers
	// If not using standard ports, we need to include the port in the URL.
	redirectHost := xHeaders.Host
	if xHeaders.Port != 80 && xHeaders.Port != 443 {
		redirectHost = net.JoinHostPort(xHeaders.Host, strconv.Itoa(xHeaders.Port))
	}

	redirectScheme := xHeaders.Proto
	if xHeaders.Port == 443 {
		redirectScheme = "https"
	}

	if xHeaders.Port == 80 {
		redirectScheme = "http"
	}

	redirectURL := &url.URL{
		Scheme: redirectScheme,
		Host:   redirectHost,
		Path:   xHeaders.Uri,
	}

	// If the URI is not empty, we need to ensure it starts with a slash
	if xHeaders.Uri != "" && xHeaders.Uri[0] != '/' {
		redirectURL.Path = "/" + xHeaders.Uri
	}

	return redirectURL, true
}

// Extracts the X-Forwarded headers from the request
func getXHeaders(r *http.Request) (*XHeaders, bool) {
	host, ok := validateHeader("X-Forwarded-Host", r)
	if !ok {
		return nil, false
	}

	proto, ok := validateHeader("X-Forwarded-Proto", r)
	if !ok {
		proto = "http" // Default to HTTP if not provided
	}

	portStr, ok := validateHeader("X-Forwarded-Port", r)
	if !ok {
		if proto == "http" {
			portStr = "80"
		} else {
			portStr = "443"
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, false
	}

	uri, ok := validateHeader("X-Forwarded-Uri", r)
	if !ok {
		uri = "/" // Default to root if not provided
	}

	// Check if the host already contains the port and strip it if necessary
	// In this case the host is set as the preferred source for the port
	splitHost, splitPort, err := net.SplitHostPort(host)
	if err == nil { // Action only needed when there is no error
		host = splitHost
		newPort, err := strconv.Atoi(splitPort)
		if err == nil {
			port = newPort
		}
	}

	return &XHeaders{
		Host:  host,
		Proto: proto,
		Port:  port,
		Uri:   uri,
	}, true
}

// Validates the presence of a specific header in the request.
func validateHeader(header string, r *http.Request) (string, bool) {
	value := r.Header.Get(header)
	if value == "" {
		return "", false
	}

	return value, true
}
