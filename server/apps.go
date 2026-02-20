package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
)

// apps maps app name -> localhost port for reverse proxying.
// ttyd sessions are registered under "terminal/{session}".
var apps sync.Map

func registerApp(name string, port int) {
	apps.Store(name, port)
}

func unregisterApp(name string) {
	apps.Delete(name)
}

// handleApp reverse-proxies HTTP and WebSocket requests to a registered app.
// URL pattern: /app/{name}/* -> 127.0.0.1:{port}/*
func handleApp(w http.ResponseWriter, r *http.Request) {
	subpath := strings.TrimPrefix(r.URL.Path, "/app/")
	slash := strings.Index(subpath, "/")
	var name, rest string
	if slash >= 0 {
		name = subpath[:slash]
		rest = subpath[slash:]
	} else {
		name = subpath
		rest = "/"
	}

	if name == "" {
		http.Error(w, "no app specified", http.StatusBadRequest)
		return
	}

	// Check for terminal/{session} prefix
	if name == "terminal" {
		// Re-parse: /app/terminal/{session}/*
		after := strings.TrimPrefix(subpath, "terminal/")
		slash2 := strings.Index(after, "/")
		if slash2 >= 0 {
			name = "terminal/" + after[:slash2]
			rest = after[slash2:]
		} else {
			name = "terminal/" + after
			rest = "/"
		}
	}

	if name == "terminal/" || name == "terminal" {
		http.Error(w, "no session specified", http.StatusBadRequest)
		return
	}

	rest = filepath.Clean(rest)

	w.Header().Set("Cache-Control", "no-store")

	portVal, ok := apps.Load(name)
	if !ok {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	port := portVal.(int)

	target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))

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

// proxyWebSocket dials the backend WebSocket and pipes data both ways.
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
