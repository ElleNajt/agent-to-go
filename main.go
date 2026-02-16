package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Track running ttyd instances
type ttydInstance struct {
	port int
	cmd  *exec.Cmd
}

// Config for spawn restrictions
type Config struct {
	AllowedCommands    []string `yaml:"allowed_commands"`
	AllowedDirectories []string `yaml:"allowed_directories"`
}

var (
	ttydInstances = make(map[string]*ttydInstance)
	portMutex     sync.Mutex
	nextPort      = 7700
	freePorts     []int // reclaimed ports to reuse
	tailscaleIP   string
	csrfToken     string  // generated at startup, required for POST requests
	config        *Config // nil = spawn disabled
)

//go:embed index.html
var indexHTML string
var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

var (
	adjectives = []string{"clever", "sleepy", "happy", "busy", "cozy", "gentle", "curious", "eager", "nimble", "quick"}
	nouns      = []string{"otter", "panda", "fox", "rabbit", "owl", "mouse", "seal", "frog", "duck", "wren"}
)

func generateCSRFToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func loadConfig() *Config {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "agent-to-go", "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil // No config = spawn disabled
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("Warning: invalid config file: %v", err)
		return nil
	}

	// Expand ~ in directory paths
	for i, dir := range cfg.AllowedDirectories {
		if strings.HasPrefix(dir, "~/") {
			cfg.AllowedDirectories[i] = filepath.Join(home, dir[2:])
		} else if dir == "~" {
			cfg.AllowedDirectories[i] = home
		}
	}

	return &cfg
}

func isCommandAllowed(cmd string) bool {
	if config == nil {
		return false
	}
	for _, allowed := range config.AllowedCommands {
		if cmd == allowed {
			return true
		}
	}
	return false
}

func isDirectoryAllowed(dir string) bool {
	if config == nil {
		return false
	}
	// Resolve to absolute path, following symlinks if the path exists
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(absDir); err == nil {
		absDir = resolved
	}
	// Check if under any allowed directory
	for _, allowed := range config.AllowedDirectories {
		absAllowed, err := filepath.Abs(allowed)
		if err != nil {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(absAllowed); err == nil {
			absAllowed = resolved
		}
		// Must be exactly the allowed dir or a subdirectory
		if absDir == absAllowed || strings.HasPrefix(absDir, absAllowed+"/") {
			return true
		}
	}
	return false
}

func validateCSRF(r *http.Request) bool {
	return subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(csrfToken)) == 1
}

func validateOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Referer is sent on form submissions when Origin isn't
		referer := r.Header.Get("Referer")
		if referer != "" {
			origin = referer
		}
	}
	// Same-origin requests may have no Origin header
	if origin == "" {
		return true
	}
	// Must come from our own server.
	// Check that origin is exactly "http://<tailscaleIP>" optionally followed by
	// a port (":...") or path ("/..."). This prevents "http://100.1.2.3.evil.com"
	// from matching when tailscaleIP is "100.1.2.3".
	allowed := "http://" + tailscaleIP
	if !strings.HasPrefix(origin, allowed) {
		return false
	}
	rest := origin[len(allowed):]
	return rest == "" || rest[0] == ':' || rest[0] == '/'
}

// validateHost checks that the Host header matches our Tailscale IP.
// This blocks DNS rebinding attacks: after rebinding, the browser sends
// Host: evil.com (the attacker's domain), not our IP. Rejecting mismatched
// Host headers prevents the attacker from reading the index page at all,
// so they can never extract the CSRF token.
func validateHost(r *http.Request) bool {
	host := r.Host
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host == tailscaleIP
}

// hostCheckMiddleware wraps an http.Handler to reject requests with wrong Host headers.
func hostCheckMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validateHost(r) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		// Prevent clickjacking — page must not be framed by other sites
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func main() {
	csrfToken = generateCSRFToken()
	config = loadConfig()

	if config != nil {
		log.Printf("Spawn enabled - allowed commands: %v", config.AllowedCommands)
		log.Printf("Spawn enabled - allowed directories: %v", config.AllowedDirectories)
	} else {
		log.Printf("Spawn disabled - no config at ~/.config/agent-to-go/config.yaml")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/connect/", handleConnect)
	mux.HandleFunc("/terminal/", handleTerminal)
	mux.HandleFunc("/spawn", handleSpawn)
	mux.HandleFunc("/spawn-project", handleSpawn) // same handler, uses "project" form field
	mux.HandleFunc("/kill/", handleKill)

	// Get Tailscale IP - fail if unavailable (security: never bind to all interfaces)
	out, err := exec.Command("tailscale", "ip", "-4").Output()
	if err != nil {
		log.Fatal("Tailscale IP not available - refusing to start. Ensure Tailscale is running and logged in.")
	}
	tailscaleIP = strings.TrimSpace(string(out))
	if tailscaleIP == "" {
		log.Fatal("Tailscale returned empty IP - refusing to start.")
	}
	addr := tailscaleIP + ":8090"

	// Clean up orphaned ttyd processes every 30 seconds
	go cleanupOrphanedTtyd()

	url := fmt.Sprintf("http://%s", addr)
	fmt.Println()
	fmt.Println("===========================================")
	fmt.Printf("  agent-to-go running at: %s\n", url)
	fmt.Println("===========================================")
	fmt.Println()
	log.Fatal(http.ListenAndServe(addr, hostCheckMiddleware(mux)))
}

// Clean up ttyd instances for sessions that no longer exist
func cleanupOrphanedTtyd() {
	for {
		time.Sleep(30 * time.Second)

		sessions, err := getTmuxSessions()
		if err != nil {
			continue
		}
		sessionSet := make(map[string]bool)
		for _, s := range sessions {
			sessionSet[s] = true
		}

		portMutex.Lock()
		for name, inst := range ttydInstances {
			if !sessionSet[name] {
				log.Printf("Cleaning up ttyd for ended session %q", name)
				inst.cmd.Process.Kill()
				inst.cmd.Wait()                          // reap zombie
				freePorts = append(freePorts, inst.port) // reclaim port
				delete(ttydInstances, name)
			}
		}
		portMutex.Unlock()
	}
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
	if inst, ok := ttydInstances[session]; ok {
		return inst.port, nil
	}

	// Reuse a free port or allocate a new one
	var port int
	if len(freePorts) > 0 {
		port = freePorts[len(freePorts)-1]
		freePorts = freePorts[:len(freePorts)-1]
	} else {
		if nextPort > 65535 {
			return 0, fmt.Errorf("no ports available")
		}
		port = nextPort
		nextPort++
	}

	// Bind ttyd to localhost only — unreachable from the network.
	// All access goes through our reverse proxy at /terminal/{session}/, which
	// enforces Host header validation (blocking DNS rebinding).
	cmd := exec.Command("ttyd", "-i", "127.0.0.1", "-p", fmt.Sprintf("%d", port), "-W", "-t", "fontSize=32", "tmux", "attach", "-t", session)
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	ttydInstances[session] = &ttydInstance{port: port, cmd: cmd}

	// Wait in background to avoid zombie processes and clean up on exit
	go func() {
		cmd.Wait()
		portMutex.Lock()
		if inst, ok := ttydInstances[session]; ok && inst.cmd == cmd {
			log.Printf("ttyd for session %q exited, cleaning up", session)
			freePorts = append(freePorts, inst.port)
			delete(ttydInstances, session)
		}
		portMutex.Unlock()
	}()
	log.Printf("Started ttyd for session %q on port %d", session, port)

	// Wait for ttyd to be ready (up to 2 seconds)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !ready {
		// ttyd probably failed to start (bad flag, missing binary, etc.)
		// Lock is already held via defer, so just clean up directly.
		delete(ttydInstances, session)
		freePorts = append(freePorts, port)
		return 0, fmt.Errorf("ttyd failed to start on port %d", port)
	}

	return port, nil
}

// Group sessions by project directory (from AGENT_TMUX_DIR env var)
func groupSessionsByProject(sessions []string) map[string][]string {
	groups := make(map[string][]string)
	for _, s := range sessions {
		project := "other"
		// Try to get project from tmux environment
		out, err := exec.Command("tmux", "show-environment", "-t", s, "AGENT_TMUX_DIR").Output()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if strings.HasPrefix(line, "AGENT_TMUX_DIR=") {
				dir := strings.TrimPrefix(line, "AGENT_TMUX_DIR=")
				// Make path relative to home directory
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

// requirePOST validates method, CSRF, and Origin for state-changing handlers.
// Returns true if the request is valid; writes an error response and returns false otherwise.
func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	if !validateCSRF(r) || !validateOrigin(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return false
	}
	return true
}

// findSession checks that a session name exists in tmux. Returns true if found.
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

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sessions, err := getTmuxSessions()
	if err != nil {
		sessions = []string{}
	}

	groups := groupSessionsByProject(sessions)

	if err := indexTmpl.Execute(w, map[string]interface{}{
		"Groups":       groups,
		"CSRFToken":    csrfToken,
		"SpawnEnabled": config != nil,
	}); err != nil {
		log.Printf("template execute error: %v", err)
	}
}

// handleTerminal reverse-proxies requests to the local ttyd instance.
// Browser hits /terminal/{session}/* -> we forward to 127.0.0.1:{port}/*
// This keeps ttyd off the network while our middleware validates Host headers.
func handleTerminal(w http.ResponseWriter, r *http.Request) {
	// Extract session name: /terminal/{session}/rest/of/path
	subpath := strings.TrimPrefix(r.URL.Path, "/terminal/")
	slash := strings.Index(subpath, "/")
	var session, rest string
	if slash >= 0 {
		session = subpath[:slash]
		rest = subpath[slash:] // includes leading /
	} else {
		session = subpath
		rest = "/"
	}

	if session == "" {
		http.Error(w, "no session specified", http.StatusBadRequest)
		return
	}

	// Clean the forwarded path to prevent traversal into unexpected ttyd paths
	rest = filepath.Clean(rest)

	// Look up the ttyd port for this session
	portMutex.Lock()
	inst, ok := ttydInstances[session]
	portMutex.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", inst.port))

	// WebSocket upgrade — proxy bidirectionally
	if r.Header.Get("Upgrade") == "websocket" {
		proxyWebSocket(w, r, target.Host, rest)
		return
	}

	// Regular HTTP — use standard reverse proxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = rest
			req.Host = target.Host
		},
	}
	proxy.ServeHTTP(w, r)
}

// proxyWebSocket dials the backend ttyd WebSocket and pipes data both ways.
func proxyWebSocket(w http.ResponseWriter, r *http.Request, backendHost, rest string) {
	// Hijack the client connection first, before touching the backend.
	// This is the standard pattern: take ownership of the client connection
	// before forwarding anything, so we don't read from a connection the
	// HTTP server still owns.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket proxy unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Connect to backend
	backendConn, err := net.Dial("tcp", backendHost)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer backendConn.Close()

	// Forward the original HTTP upgrade request to backend
	// Rewrite the request path and Host, keep all other headers (Upgrade, Sec-WebSocket-*, etc.)
	r.URL.Path = rest
	r.Host = backendHost
	r.Header.Set("Host", backendHost)
	if err := r.Write(backendConn); err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Bidirectional pipe
	done := make(chan struct{}, 2)
	go func() { io.Copy(backendConn, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, backendConn); done <- struct{}{} }()
	<-done
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

	// Validate session exists (also prevents injection - only real session names accepted)
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

// Get directory for a project by checking existing sessions
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
				// Found a session for this project, get its directory
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

// Generate a unique session name
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
	// Fallback with timestamp
	return fmt.Sprintf("%s-%s-%d", cmd, project, time.Now().Unix())
}

// Spawn a new session in a directory
func spawnSession(dir, cmd string) (string, error) {
	// Check directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("directory not found: %s", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", dir)
	}

	project := filepath.Base(dir)
	session := generateSessionName(cmd, project)

	// Create detached tmux session
	tmux := exec.Command("tmux", "new-session", "-d", "-s", session, "-c", dir, "--", cmd)
	if err := tmux.Run(); err != nil {
		return "", err
	}

	// Store environment variables
	exec.Command("tmux", "set-environment", "-t", session, "AGENT_TMUX_DIR", dir).Run()
	exec.Command("tmux", "set-environment", "-t", session, "AGENT_TMUX_CMD", cmd).Run()

	return session, nil
}

// handleSpawn creates a new tmux session and connects to it.
// Accepts either "dir" (explicit directory) or "project" (looked up from existing sessions).
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

	// Resolve directory from project name if no explicit dir
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

	// Expand ~ to home directory
	if strings.HasPrefix(dir, "~") {
		dir = home + dir[1:]
	}

	// Resolve to absolute and clean path (handles ../)
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

	// Validate against allowlists
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

	// Validate session exists
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

	// Kill the tmux session
	exec.Command("tmux", "kill-session", "-t", session).Run()

	http.Redirect(w, r, "/", http.StatusFound)
}
