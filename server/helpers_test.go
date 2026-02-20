package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	csrf "filippo.io/csrf/gorilla"
)

// newCSRFHandler wraps a handler with filippo.io/csrf for testing.
// filippo.io/csrf uses Sec-Fetch-Site and Origin headers instead of tokens.
func newCSRFHandler(handler http.Handler) http.Handler {
	return csrf.Protect(nil)(handler)
}

// crossSitePost makes a POST that looks like a cross-origin browser request.
// filippo.io/csrf blocks these based on Sec-Fetch-Site header.
func crossSitePost(t *testing.T, handler http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// sameSitePost makes a POST that looks like a same-origin browser request.
// filippo.io/csrf allows these.
func sameSitePost(t *testing.T, handler http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// postWithCSRF makes a same-origin POST (the legitimate case).
// Kept for backward compatibility with existing tests.
func postWithCSRF(t *testing.T, handler http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	return sameSitePost(t, handler, path, form)
}
