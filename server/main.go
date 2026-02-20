package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"tailscale.com/tsnet"
)

func main() {
	machineHostname, _ := os.Hostname()
	// Strip .local suffix if present (macOS)
	machineHostname = strings.TrimSuffix(machineHostname, ".local")
	machineHostname = strings.ToLower(machineHostname)

	ts := &tsnet.Server{
		Hostname: "agent-to-go-" + machineHostname,
	}
	defer ts.Close()

	ln, err := ts.ListenTLS("tcp", ":443")
	if err != nil {
		log.Fatalf("tsnet ListenTLS: %v", err)
	}
	defer ln.Close()

	status, err := ts.Up(context.Background())
	if err != nil {
		log.Fatalf("tsnet Up: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/connect/", handleConnect)
	mux.HandleFunc("/app/", handleApp)
	mux.HandleFunc("/spawn", handleSpawn)
	mux.HandleFunc("/spawn-project", handleSpawn)
	mux.HandleFunc("/kill/", handleKill)

	csrfMiddleware := newCSRFMiddleware()

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
