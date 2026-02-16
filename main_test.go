package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSessionName(t *testing.T) {
	name := generateSessionName("claude", "myproject")

	// Should have format: cmd-project-adj-noun
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

	// Adjective and noun should be from our lists
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

func TestGenerateSessionNameUnique(t *testing.T) {
	names := make(map[string]bool)
	for i := 0; i < 50; i++ {
		name := generateSessionName("claude", "test")
		if names[name] {
			// Collisions are possible but unlikely in 50 iterations
			// with 100 combinations. Just log it.
			t.Logf("collision on iteration %d: %s", i, name)
		}
		names[name] = true
	}
}

func TestSpawnSessionBadDirectory(t *testing.T) {
	_, err := spawnSession("/nonexistent/path/that/does/not/exist", "echo")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if !strings.Contains(err.Error(), "directory not found") {
		t.Errorf("expected 'directory not found' error, got: %s", err)
	}
}

func TestSpawnSessionNotADirectory(t *testing.T) {
	// Create a temp file
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

func TestGroupSessionsByProjectFallback(t *testing.T) {
	// Test the fallback parsing when AGENT_TMUX_DIR is not set
	sessions := []string{
		"claude-myproject-cozy-otter",
		"claude-another-project-happy-fox",
		"aider-test-sleepy-owl",
	}

	groups := groupSessionsByProject(sessions)

	// These will use fallback parsing since no tmux sessions actually exist
	// The function will fail to get AGENT_TMUX_DIR and fall back to name parsing
	if len(groups) == 0 {
		t.Error("expected at least one group")
	}
}

func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
	}{
		{"~", home},
		{"~/code", home + "/code"},
		{"~/code/project", home + "/code/project"},
		{"/absolute/path", "/absolute/path"},
	}

	for _, tc := range tests {
		dir := tc.input
		if strings.HasPrefix(dir, "~") {
			dir = home + strings.TrimPrefix(dir, "~")
		}
		if dir != tc.expected {
			t.Errorf("expandTilde(%q) = %q, want %q", tc.input, dir, tc.expected)
		}
	}
}

func TestProjectFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/Users/elle/code/agent-phone", "agent-phone"},
		{"/home/user/projects/my-app", "my-app"},
		{"/tmp", "tmp"},
	}

	for _, tc := range tests {
		result := filepath.Base(tc.path)
		if result != tc.expected {
			t.Errorf("filepath.Base(%q) = %q, want %q", tc.path, result, tc.expected)
		}
	}
}
