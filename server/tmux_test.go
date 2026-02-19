package main

import (
	"os"
	"strings"
	"testing"
)

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
