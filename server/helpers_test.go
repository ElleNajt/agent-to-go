package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
)

func init() {
	config = &Config{
		AllowedCommands:    []string{"claude", "codex", "echo"},
		AllowedDirectories: []string{"/tmp", "/Users/elle/code"},
	}
}

var csrfTestKey = []byte("test-key-must-be-32-bytes-long!!")

// newCSRFHandler wraps a handler with gorilla/csrf for testing.
func newCSRFHandler(handler http.Handler) http.Handler {
	return csrf.Protect(
		csrfTestKey,
		csrf.Secure(false),
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.Path("/"),
	)(handler)
}

// getCSRFToken does a GET to the index page to extract a valid CSRF cookie + token pair.
func getCSRFToken(t *testing.T, handler http.Handler) (string, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /: expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	marker := `name="gorilla.csrf.Token" value="`
	idx := strings.Index(body, marker)
	if idx == -1 {
		t.Fatalf("CSRF token field not found in response body")
	}
	start := idx + len(marker)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		t.Fatalf("CSRF token value not terminated")
	}
	token := body[start : start+end]

	return token, w.Result().Cookies()
}

// postWithCSRF makes a POST request with a valid CSRF token.
func postWithCSRF(t *testing.T, handler http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	token, cookies := getCSRFToken(t, handler)

	form.Set("gorilla.csrf.Token", token)
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Mark as plaintext HTTP so gorilla/csrf skips the Referer check.
	req = csrf.PlaintextHTTPRequest(req)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}
