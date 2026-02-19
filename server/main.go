package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/csrf"
	"tailscale.com/tsnet"
)

func main() {
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
