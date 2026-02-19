package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ttydInstance struct {
	port int
	cmd  *exec.Cmd
}

var (
	ttydInstances = make(map[string]*ttydInstance)
	portMutex     sync.Mutex
	nextPort      = 7700
	freePorts     []int // reclaimed ports to reuse
)

// startTtyd launches a ttyd process for a tmux session, bound to localhost only.
// Returns the port number. Reuses an existing instance if already running.
func startTtyd(session string) (int, error) {
	portMutex.Lock()
	defer portMutex.Unlock()

	if inst, ok := ttydInstances[session]; ok {
		return inst.port, nil
	}

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

	// Bind to localhost only — unreachable from the network.
	// All access goes through our reverse proxy at /terminal/{session}/.
	cmd := exec.Command("ttyd", "-i", "127.0.0.1", "-p", fmt.Sprintf("%d", port), "-W", "-t", "fontSize=32", "tmux", "attach", "-t", session)
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	ttydInstances[session] = &ttydInstance{port: port, cmd: cmd}

	// Reap zombie and reclaim port when ttyd exits
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
		// Kill the process — the background goroutine (line 71) will
		// reap it, reclaim the port, and delete from ttydInstances.
		// Don't touch ttydInstances or freePorts here to avoid a
		// double-reclaim race.
		cmd.Process.Kill()
		return 0, fmt.Errorf("ttyd failed to start on port %d", port)
	}

	return port, nil
}

// cleanupOrphanedTtyd periodically kills ttyd instances for sessions that no longer exist.
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

// handleTerminal reverse-proxies HTTP and WebSocket requests to the local ttyd instance.
// Browser hits /terminal/{session}/* -> we forward to 127.0.0.1:{port}/*
func handleTerminal(w http.ResponseWriter, r *http.Request) {
	subpath := strings.TrimPrefix(r.URL.Path, "/terminal/")
	slash := strings.Index(subpath, "/")
	var session, rest string
	if slash >= 0 {
		session = subpath[:slash]
		rest = subpath[slash:]
	} else {
		session = subpath
		rest = "/"
	}

	if session == "" {
		http.Error(w, "no session specified", http.StatusBadRequest)
		return
	}

	rest = filepath.Clean(rest)

	w.Header().Set("Cache-Control", "no-store")

	portMutex.Lock()
	inst, ok := ttydInstances[session]
	portMutex.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", inst.port))

	if r.Header.Get("Upgrade") == "websocket" {
		if !checkWebSocketOrigin(w, r) {
			return
		}
		proxyWebSocket(w, r, target.Host, rest)
		return
	}

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

	backendConn, err := net.Dial("tcp", backendHost)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer backendConn.Close()

	r.URL.Path = rest
	r.Host = backendHost
	r.Header.Set("Host", backendHost)
	if err := r.Write(backendConn); err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(backendConn, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, backendConn); done <- struct{}{} }()
	<-done
}
