package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newCSRFHandler wraps a handler with net/http.CrossOriginProtection for testing.
func newCSRFHandler(handler http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	return cop.Handler(handler)
}

// crossSitePost makes a POST that looks like a cross-origin browser request.
// CrossOriginProtection blocks these based on Sec-Fetch-Site header.
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
// CrossOriginProtection allows these.
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
