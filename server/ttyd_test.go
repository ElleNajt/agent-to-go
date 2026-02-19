package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTerminalProxy_NoSessionReturns400(t *testing.T) {
	req := httptest.NewRequest("GET", "/terminal/", nil)
	w := httptest.NewRecorder()
	handleTerminal(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("empty session name: expected 400, got %d", w.Code)
	}
}

func TestTerminalProxy_UnknownSessionReturns404(t *testing.T) {
	req := httptest.NewRequest("GET", "/terminal/nonexistent-session/", nil)
	w := httptest.NewRecorder()
	handleTerminal(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("nonexistent session: expected 404, got %d", w.Code)
	}
}

func TestTerminalProxy_KnownSessionProxies(t *testing.T) {
	fakeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proxied", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fake ttyd response"))
	})
	fakeTtyd := httptest.NewServer(fakeHandler)
	defer fakeTtyd.Close()

	fakeTtydAddr := fakeTtyd.Listener.Addr().String()
	fakePort := 0
	fmt.Sscanf(fakeTtydAddr, "127.0.0.1:%d", &fakePort)
	if fakePort == 0 {
		fmt.Sscanf(fakeTtydAddr, "[::1]:%d", &fakePort)
	}
	if fakePort == 0 {
		t.Fatalf("cannot parse port from test server addr: %s", fakeTtydAddr)
	}

	portMutex.Lock()
	ttydInstances["test-proxy-session"] = &ttydInstance{port: fakePort, cmd: nil}
	portMutex.Unlock()
	defer func() {
		portMutex.Lock()
		delete(ttydInstances, "test-proxy-session")
		portMutex.Unlock()
	}()

	req := httptest.NewRequest("GET", "/terminal/test-proxy-session/", nil)
	w := httptest.NewRecorder()
	handleTerminal(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("proxy to fake ttyd: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "fake ttyd response") {
		t.Errorf("proxy did not forward to fake ttyd, got: %s", w.Body.String())
	}
}
