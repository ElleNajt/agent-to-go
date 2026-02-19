package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGETNotAllowed(t *testing.T) {
	endpoints := []string{
		"/connect/test-session",
		"/spawn",
		"/spawn-project",
		"/kill/test-session",
	}

	for _, path := range endpoints {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()

		switch {
		case strings.HasPrefix(path, "/connect/"):
			handleConnect(w, req)
		case path == "/spawn" || path == "/spawn-project":
			handleSpawn(w, req)
		case strings.HasPrefix(path, "/kill/"):
			handleKill(w, req)
		}

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: expected 405, got %d", path, w.Code)
		}
	}
}

func TestOtherMethodsNotAllowed(t *testing.T) {
	methods := []string{"PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	for _, method := range methods {
		req := httptest.NewRequest(method, "/spawn", nil)
		w := httptest.NewRecorder()
		handleSpawn(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /spawn: expected 405, got %d", method, w.Code)
		}
	}
}

func TestConnectRejectsInvalidSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/connect/", handleConnect)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	w := postWithCSRF(t, handler, "/connect/fake-session-that-does-not-exist", form)

	if w.Code != http.StatusNotFound {
		t.Errorf("connect to fake session: expected 404, got %d", w.Code)
	}
}

func TestKillRejectsInvalidSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/kill/", handleKill)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	w := postWithCSRF(t, handler, "/kill/fake-session-that-does-not-exist", form)

	if w.Code != http.StatusNotFound {
		t.Errorf("kill fake session: expected 404, got %d", w.Code)
	}
}
