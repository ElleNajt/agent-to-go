package main

// Security primitives for agent-to-go.
//
// The security model is layered:
//   1. Tailscale (network)  — only tailnet members can reach the server
//   2. TLS (transport)      — tsnet provides automatic Let's Encrypt certs
//   3. CSRF (request forge) — filippo.io/csrf using Sec-Fetch-Site headers
//   4. POST enforcement     — mutating endpoints reject non-POST methods
//   5. WebSocket Origin     — cross-origin WebSocket upgrades are blocked
//
// This file contains all web security configuration and enforcement.
// Read this file to understand the web security posture.
//
// Non-web security decisions (127.0.0.1 binding, exec.Command flags)
// live in ttyd.go and tmux.go.

import (
	"net/http"
	"net/url"

	csrf "filippo.io/csrf/gorilla"
)

// newCSRFMiddleware returns CSRF protection middleware.
// filippo.io/csrf uses browser Sec-Fetch-Site and Origin headers
// to block cross-origin requests. No tokens or cookies needed.
func newCSRFMiddleware() func(http.Handler) http.Handler {
	return csrf.Protect(nil)
}

// requirePOST checks that the request method is POST.
// CSRF validation is handled by the CSRF middleware.
func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// checkWebSocketOrigin validates the Origin header on WebSocket upgrades.
// Browsers send Origin on WebSocket handshakes and it cannot be forged
// by a cross-origin page. Returns true if the request should proceed.
func checkWebSocketOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Host != r.Host {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	return true
}
