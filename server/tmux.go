package main

import (
	"fmt"
	mathrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	adjectives = []string{"clever", "sleepy", "happy", "busy", "cozy", "gentle", "curious", "eager", "nimble", "quick"}
	nouns      = []string{"otter", "panda", "fox", "rabbit", "owl", "mouse", "seal", "frog", "duck", "wren"}
)

// getTmuxSessions lists all tmux session names.
func getTmuxSessions() ([]string, error) {
	out, err := exec.Command("tmux", "list-sessions", "-F", "#{session_name}").Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var sessions []string
	for _, line := range lines {
		if line != "" {
			sessions = append(sessions, line)
		}
	}
	return sessions, nil
}

// findSession checks that a session name exists in tmux.
func findSession(session string) (bool, error) {
	sessions, err := getTmuxSessions()
	if err != nil {
		return false, err
	}
	for _, s := range sessions {
		if s == session {
			return true, nil
		}
	}
	return false, nil
}

// groupSessionsByProject groups sessions by their project directory.
func groupSessionsByProject(sessions []string) map[string][]string {
	groups := make(map[string][]string)
	for _, s := range sessions {
		project := "other"
		out, err := exec.Command("tmux", "show-environment", "-t", s, "AGENT_TMUX_DIR").Output()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if strings.HasPrefix(line, "AGENT_TMUX_DIR=") {
				dir := strings.TrimPrefix(line, "AGENT_TMUX_DIR=")
				home, _ := os.UserHomeDir()
				if dir == home {
					project = "~"
				} else if strings.HasPrefix(dir, home+"/") {
					project = strings.TrimPrefix(dir, home+"/")
				} else {
					project = dir
				}
			}
		} else {
			// Fallback: parse from session name (cmd-PROJECT-adj-noun)
			parts := strings.Split(s, "-")
			if len(parts) >= 4 {
				project = strings.Join(parts[1:len(parts)-2], "-")
			} else if len(parts) >= 2 {
				project = parts[1]
			}
		}
		groups[project] = append(groups[project], s)
	}
	return groups
}

// generateSessionName creates a unique session name like "claude-myproject-cozy-otter".
func generateSessionName(cmd, project string) string {
	sessions, _ := getTmuxSessions()
	sessionSet := make(map[string]bool)
	for _, s := range sessions {
		sessionSet[s] = true
	}

	for i := 0; i < 10; i++ {
		adj := adjectives[mathrand.Intn(len(adjectives))]
		noun := nouns[mathrand.Intn(len(nouns))]
		name := fmt.Sprintf("%s-%s-%s-%s", cmd, project, adj, noun)
		if !sessionSet[name] {
			return name
		}
	}
	return fmt.Sprintf("%s-%s-%d", cmd, project, time.Now().Unix())
}

// spawnSession creates a new detached tmux session running cmd in dir.
func spawnSession(dir, cmd string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("directory not found: %s", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", dir)
	}

	project := filepath.Base(dir)
	session := generateSessionName(cmd, project)

	tmux := exec.Command("tmux", "new-session", "-d", "-s", session, "-c", dir, "--", cmd)
	if err := tmux.Run(); err != nil {
		return "", err
	}

	exec.Command("tmux", "set-environment", "-t", session, "AGENT_TMUX_DIR", dir).Run()
	exec.Command("tmux", "set-environment", "-t", session, "AGENT_TMUX_CMD", cmd).Run()

	return session, nil
}

// getProjectDir finds the directory for a project by checking existing sessions.
func getProjectDir(project string) string {
	sessions, err := getTmuxSessions()
	if err != nil {
		return ""
	}
	for _, s := range sessions {
		parts := strings.Split(s, "-")
		if len(parts) >= 4 {
			sessionProject := strings.Join(parts[1:len(parts)-2], "-")
			if sessionProject == project {
				out, err := exec.Command("tmux", "show-environment", "-t", s, "AGENT_TMUX_DIR").Output()
				if err == nil {
					line := strings.TrimSpace(string(out))
					if strings.HasPrefix(line, "AGENT_TMUX_DIR=") {
						return strings.TrimPrefix(line, "AGENT_TMUX_DIR=")
					}
				}
			}
		}
	}
	return ""
}
