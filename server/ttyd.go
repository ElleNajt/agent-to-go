package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
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

	if len(ttydInstances) >= 100 {
		return 0, fmt.Errorf("too many concurrent sessions (max 100)")
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
	// All access goes through the reverse proxy at /app/terminal/{session}/.
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
			unregisterApp("terminal/" + session)
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
		cmd.Process.Kill()
		return 0, fmt.Errorf("ttyd failed to start on port %d", port)
	}

	registerApp("terminal/"+session, port)

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
				unregisterApp("terminal/" + name)
			}
		}
		portMutex.Unlock()
	}
}
