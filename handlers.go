package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gorilla/csrf"
)

//go:embed index.html
var indexHTML string
var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

// requirePOST checks that the request method is POST.
// CSRF validation is handled by gorilla/csrf middleware.
func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sessions, err := getTmuxSessions()
	if err != nil {
		sessions = []string{}
	}

	groups := groupSessionsByProject(sessions)

	if err := indexTmpl.Execute(w, map[string]interface{}{
		"Groups":       groups,
		"CSRFField":    csrf.TemplateField(r),
		"SpawnEnabled": config != nil,
	}); err != nil {
		log.Printf("template execute error: %v", err)
	}
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}

	session := strings.TrimPrefix(r.URL.Path, "/connect/")
	if session == "" {
		http.Error(w, "no session specified", http.StatusBadRequest)
		return
	}

	found, err := findSession(session)
	if err != nil {
		log.Printf("getTmuxSessions error: %v", err)
		http.Error(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	if _, err = startTtyd(session); err != nil {
		log.Printf("startTtyd error for session %q: %v", session, err)
		http.Error(w, "failed to start terminal", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/terminal/%s/", session), http.StatusFound)
}

func handleSpawn(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if config == nil {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	dir := r.FormValue("dir")
	project := r.FormValue("project")

	if dir == "" && project == "" {
		http.Error(w, "dir or project required", http.StatusBadRequest)
		return
	}

	home, _ := os.UserHomeDir()

	if dir == "" {
		dir = getProjectDir(project)
		if dir == "" {
			if project == "~" {
				dir = home
			} else if strings.HasPrefix(project, "/") {
				dir = project
			} else {
				dir = filepath.Join(home, project)
			}
		}
	}

	if strings.HasPrefix(dir, "~") {
		dir = home + dir[1:]
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		http.Error(w, "invalid directory path", http.StatusBadRequest)
		return
	}
	dir = absDir

	cmd := r.FormValue("cmd")
	if cmd == "" {
		cmd = "claude"
	}

	if !isCommandAllowed(cmd) {
		log.Printf("spawn rejected: command %q not allowed", cmd)
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if !isDirectoryAllowed(dir) {
		log.Printf("spawn rejected: directory %q not allowed", dir)
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	session, err := spawnSession(dir, cmd)
	if err != nil {
		log.Printf("spawnSession error: %v", err)
		http.Error(w, "failed to spawn session", http.StatusInternalServerError)
		return
	}

	if _, err = startTtyd(session); err != nil {
		log.Printf("startTtyd error for session %q: %v", session, err)
		http.Error(w, "failed to start terminal", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/terminal/%s/", session), http.StatusFound)
}

func handleKill(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}

	session := strings.TrimPrefix(r.URL.Path, "/kill/")
	if session == "" {
		http.Error(w, "session required", http.StatusBadRequest)
		return
	}

	found, err := findSession(session)
	if err != nil {
		log.Printf("getTmuxSessions error: %v", err)
		http.Error(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	exec.Command("tmux", "kill-session", "-t", session).Run()

	http.Redirect(w, r, "/", http.StatusFound)
}
