package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
)

// Track running ttyd instances: session name -> port
var (
	ttydPorts   = make(map[string]int)
	portMutex   sync.Mutex
	nextPort    = 7700
	tailscaleIP string
)

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/connect/", handleConnect)

	// Get Tailscale IP
	out, err := exec.Command("tailscale", "ip", "-4").Output()
	var addr string
	if err != nil {
		addr = ":8090"
		log.Printf("Warning: couldn't get Tailscale IP, binding to all interfaces")
	} else {
		tailscaleIP = strings.TrimSpace(string(out))
		addr = tailscaleIP + ":8090"
	}

	log.Printf("Claude Phone picker running on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// List tmux sessions
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

// Start ttyd for a session, return port
func startTtyd(session string) (int, error) {
	portMutex.Lock()
	defer portMutex.Unlock()

	// Already running?
	if port, ok := ttydPorts[session]; ok {
		return port, nil
	}

	port := nextPort
	nextPort++

	// Bind ttyd to Tailscale IP (or all interfaces if not available)
	var cmd *exec.Cmd
	if tailscaleIP != "" {
		cmd = exec.Command("ttyd", "-i", tailscaleIP, "-p", fmt.Sprintf("%d", port), "-W", "tmux", "attach", "-t", session)
	} else {
		cmd = exec.Command("ttyd", "-p", fmt.Sprintf("%d", port), "-W", "tmux", "attach", "-t", session)
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	ttydPorts[session] = port
	log.Printf("Started ttyd for session %q on port %d", session, port)
	return port, nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	sessions, err := getTmuxSessions()
	if err != nil {
		sessions = []string{}
	}

	tmpl := template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Claude Sessions</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: #1a1a2e;
            color: #eee;
            margin: 0;
            padding: 16px;
        }
        h1 {
            font-size: 24px;
            margin-bottom: 20px;
        }
        .session {
            display: block;
            background: #16213e;
            border: 1px solid #0f3460;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 12px;
            text-decoration: none;
            color: #eee;
            font-size: 18px;
        }
        .session:active {
            background: #0f3460;
        }
        .empty {
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>
    <h1>Claude Sessions</h1>
    {{if .Sessions}}
        {{range .Sessions}}
        <a class="session" href="/connect/{{.}}">{{.}}</a>
        {{end}}
    {{else}}
        <p class="empty">No tmux sessions running</p>
    {{end}}
</body>
</html>`))

	tmpl.Execute(w, map[string]interface{}{
		"Sessions": sessions,
	})
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	session := strings.TrimPrefix(r.URL.Path, "/connect/")
	if session == "" {
		http.Error(w, "no session specified", http.StatusBadRequest)
		return
	}

	port, err := startTtyd(session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to ttyd
	// Use same host but different port
	host := strings.Split(r.Host, ":")[0]
	http.Redirect(w, r, fmt.Sprintf("http://%s:%d", host, port), http.StatusFound)
}
