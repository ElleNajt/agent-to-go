package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/csrf"
	"tailscale.com/tsnet"
)

// loadOrCreateCSRFKey reads or creates a persistent 32-byte CSRF key.
// gorilla/csrf needs this key to HMAC-sign cookies; it must persist
// across restarts so existing cookies remain valid.
func loadOrCreateCSRFKey(stateDir string) ([]byte, error) {
	keyPath := filepath.Join(stateDir, "csrf-key")
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == 32 {
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating CSRF key: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("writing CSRF key: %w", err)
	}
	return key, nil
}

func main() {
	config = loadConfig()

	if config != nil {
		log.Printf("Spawn enabled - allowed commands: %v", config.AllowedCommands)
		log.Printf("Spawn enabled - allowed directories: %v", config.AllowedDirectories)
	} else {
		log.Printf("Spawn disabled - no config at ~/.config/agent-to-go/config.yaml")
	}

	// tsnet embeds a Tailscale node directly in the process.
	// Provides automatic TLS via Let's Encrypt for *.ts.net domains.
	ts := &tsnet.Server{
		Hostname: "agent-to-go",
	}
	defer ts.Close()

	ln, err := ts.ListenTLS("tcp", ":443")
	if err != nil {
		log.Fatalf("tsnet ListenTLS: %v", err)
	}
	defer ln.Close()

	status, err := ts.Up(nil)
	if err != nil {
		log.Fatalf("tsnet Up: %v", err)
	}

	home, _ := os.UserHomeDir()
	stateDir := filepath.Join(home, ".config", "agent-to-go")
	csrfKey, err := loadOrCreateCSRFKey(stateDir)
	if err != nil {
		log.Fatalf("CSRF key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/connect/", handleConnect)
	mux.HandleFunc("/terminal/", handleTerminal)
	mux.HandleFunc("/spawn", handleSpawn)
	mux.HandleFunc("/spawn-project", handleSpawn)
	mux.HandleFunc("/kill/", handleKill)

	// gorilla/csrf: double-submit cookie, SameSite Strict,
	// Referer checking (automatic for HTTPS), BREACH mitigation.
	csrfMiddleware := csrf.Protect(
		csrfKey,
		csrf.Secure(true),
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.Path("/"),
	)

	go cleanupOrphanedTtyd()

	hostname := "agent-to-go"
	if len(status.CertDomains) > 0 {
		hostname = status.CertDomains[0]
	}
	fmt.Println()
	fmt.Println("===========================================")
	fmt.Printf("  agent-to-go running at: https://%s\n", hostname)
	fmt.Println("===========================================")
	fmt.Println()

	// http.Serve (not ServeTLS) — ListenTLS already terminates TLS
	log.Fatal(http.Serve(ln, csrfMiddleware(mux)))
}
