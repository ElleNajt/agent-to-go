package main

// Security primitives for agent-to-go.
//
// The security model is layered:
//   1. Tailscale (network)  — only tailnet members can reach the server
//   2. TLS (transport)      — tsnet provides automatic Let's Encrypt certs
//   3. CSRF (request forge) — gorilla/csrf double-submit cookie, SameSite Strict
//   4. POST enforcement     — mutating endpoints reject non-POST methods
//   5. WebSocket Origin     — cross-origin WebSocket upgrades are blocked
//
// This file contains all web security logic. Read this one file to
// understand the web security posture. Non-web security decisions
// (127.0.0.1 binding, exec.Command flags) live in ttyd.go and tmux.go.

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/gorilla/csrf"
)

// loadOrCreateCSRFKey reads or creates a persistent 32-byte CSRF key.
// gorilla/csrf needs this key to HMAC-sign cookies; it must persist
// across restarts so existing cookies remain valid.
func loadOrCreateCSRFKey(stateDir string) ([]byte, error) {
	keyPath := filepath.Join(stateDir, "csrf-key")
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == 32 {
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating CSRF key: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("writing CSRF key: %w", err)
	}
	return key, nil
}

// newCSRFMiddleware configures gorilla/csrf for this application.
//   - Secure(true): cookie only sent over HTTPS
//   - SameSite Strict: cookie never sent on cross-origin requests
//   - Path("/"): cookie covers all routes
//
// gorilla/csrf additionally provides:
//   - Double-submit cookie pattern (token in cookie + form body, HMAC-verified)
//   - Per-request token masking (BREACH mitigation)
//   - Referer checking on HTTPS (rejects cross-origin POST)
//   - HttpOnly cookies by default
//   - Safe methods (GET, HEAD, OPTIONS, TRACE) are not checked
func newCSRFMiddleware(key []byte) func(http.Handler) http.Handler {
	return csrf.Protect(
		key,
		csrf.Secure(true),
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.Path("/"),
	)
}

// requirePOST checks that the request method is POST.
// CSRF validation is handled by gorilla/csrf middleware.
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
