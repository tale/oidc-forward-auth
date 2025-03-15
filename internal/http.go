package oidc_forward_auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func RegisterHandlers(config *Config, oauth2 *OidcClient) {
	http.HandleFunc("/_health", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(config.CookieName)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Cookie: nil"))
			return
		}

		body := fmt.Sprintf("Cookie: %s", cookie)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log := GetLogger()

		valid, cookie := CheckCookieAuth(config, r)
		if valid {
			if cookie != nil {
				http.SetCookie(w, cookie)
			}

			w.WriteHeader(http.StatusOK)
			return
		}

		// To construct the "true" redirect URI we need the following:
		// - X-Forwarded-Proto
		// - X-Forwarded-Host
		// - X-Forwarded-Uri
		// - X-Forwarded-Port (Special, we check if X-Forwarded-Host already contains the port)
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Missing X-Forwarded-Host"))
			return
		}

		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			// Assume HTTP (This behavior could be bad)
			proto = "http"
		}

		// Handle default ports first
		port := r.Header.Get("X-Forwarded-Port")
		if port == "" {
			if proto == "http" {
				port = "80"
			} else {
				port = "443"
			}
		}

		// Check if the host already contains the port by trying to split
		_, _, err := net.SplitHostPort(host)
		if err != nil {
			// If we get an error, we need to append the port
			host = net.JoinHostPort(host, port)
		}

		uri := r.Header.Get("X-Forwarded-Uri")
		if uri == "" {
			uri = "/"
		}

		url := &url.URL{
			Scheme: proto,
			Host:   host,
			Path:   uri,
		}

		log.Debug("Storing URL %s for %s", url.String(), r.RemoteAddr)
		state, err := GenerateState(url.String())
		if err != nil {
			http.Error(w, "Failed to generate state", http.StatusInternalServerError)
			return
		}

		nonce, err := GenerateNonce()
		if err != nil {
			http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
			return
		}

		flowCookie, err := IssueCookie(config, &CookieClaims{
			State: state,
			Nonce: nonce,
		})

		if err != nil {
			http.Error(w, "Failed to issue cookie", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, flowCookie)
		authUrl := oauth2.AuthCodeURL(state, oidc.Nonce(nonce))
		http.Redirect(w, r, authUrl, http.StatusFound)
	})

	http.HandleFunc("/oidc", func(w http.ResponseWriter, r *http.Request) {
		log := GetLogger()

		cookie, err := r.Cookie(config.CookieName)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Missing cookie"))
			return
		}

		claims, err := DecodeCookie(config, cookie)
		if err != nil {
			log.Error("Unable to decode cookie from %s: %v", r.RemoteAddr, err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Failed to decode cookie"))
		}

		state := r.URL.Query().Get("state")
		if state != claims.State {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid state"))
			return
		}

		// We need the id_token to verify the nonce
		ctx := context.Background()
		oauth2Token, err := oauth2.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := oauth2.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if claims.Nonce != idToken.Nonce {
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}

		// Make an expiry using the config (CookieExpiry is in minutes)
		exp := time.Now().Add(time.Duration(config.CookieExpiry) * time.Minute)
		cookie, err = IssueCookie(config, &CookieClaims{
			Expiry: exp.Unix(),
		})

		if err != nil {
			http.Error(w, "Failed to issue cookie", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, cookie)
		url, err := GetURLFromState(claims.State)
		if err != nil {
			http.Error(w, "Failed to get URL from state", http.StatusInternalServerError)
			return
		}

		log.Debug("Redirecting %s to %s", r.RemoteAddr, url)
		http.Redirect(w, r, url, http.StatusFound)
	})

}
