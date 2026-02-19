package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

func TestSpawnRejectsNonexistentDirectory(t *testing.T) {
	_, err := spawnSession("/nonexistent/path/that/does/not/exist", "echo")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if !strings.Contains(err.Error(), "directory not found") {
		t.Errorf("expected 'directory not found' error, got: %s", err)
	}
}

func TestSpawnRejectsFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	_, err = spawnSession(tmpFile.Name(), "echo")
	if err == nil {
		t.Error("expected error for file (not directory)")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %s", err)
	}
}

func TestGenerateSessionName(t *testing.T) {
	name := generateSessionName("claude", "myproject")

	parts := strings.Split(name, "-")
	if len(parts) != 4 {
		t.Errorf("expected 4 parts, got %d: %s", len(parts), name)
	}
	if parts[0] != "claude" {
		t.Errorf("expected cmd 'claude', got '%s'", parts[0])
	}
	if parts[1] != "myproject" {
		t.Errorf("expected project 'myproject', got '%s'", parts[1])
	}

	foundAdj := false
	for _, adj := range adjectives {
		if adj == parts[2] {
			foundAdj = true
			break
		}
	}
	if !foundAdj {
		t.Errorf("adjective '%s' not in list", parts[2])
	}

	foundNoun := false
	for _, noun := range nouns {
		if noun == parts[3] {
			foundNoun = true
			break
		}
	}
	if !foundNoun {
		t.Errorf("noun '%s' not in list", parts[3])
	}
}
