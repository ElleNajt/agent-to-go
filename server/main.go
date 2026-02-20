package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"tailscale.com/tsnet"
)

type webAppFlag []string

func (f *webAppFlag) String() string { return strings.Join(*f, ", ") }
func (f *webAppFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	var webApps webAppFlag
	flag.Var(&webApps, "web-app", "Register a web app as name=port (e.g. --web-app grafana=3000)")
	flag.Parse()

	for _, spec := range webApps {
		parts := strings.SplitN(spec, "=", 2)
		if len(parts) != 2 {
			log.Fatalf("invalid --web-app flag %q: expected name=port", spec)
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatalf("invalid port in --web-app %q: %v", spec, err)
		}
		registerApp(parts[0], port)
		log.Printf("Registered web app %q on port %d", parts[0], port)
	}

	ts := &tsnet.Server{
		Hostname: "agent-to-go-fugue",
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
