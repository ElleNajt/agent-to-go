package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApp_NoAppReturns400(t *testing.T) {
	req := httptest.NewRequest("GET", "/app/", nil)
	w := httptest.NewRecorder()
	handleApp(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("empty app name: expected 400, got %d", w.Code)
	}
}

func TestApp_NoSessionReturns400(t *testing.T) {
	req := httptest.NewRequest("GET", "/app/terminal/", nil)
	w := httptest.NewRecorder()
	handleApp(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("empty session name: expected 400, got %d", w.Code)
	}
}

func TestApp_UnknownSessionReturns404(t *testing.T) {
	req := httptest.NewRequest("GET", "/app/terminal/nonexistent-session/", nil)
	w := httptest.NewRecorder()
	handleApp(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("nonexistent session: expected 404, got %d", w.Code)
	}
}

func TestApp_UnknownAppReturns404(t *testing.T) {
	req := httptest.NewRequest("GET", "/app/grafana/", nil)
	w := httptest.NewRecorder()
	handleApp(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("unregistered app: expected 404, got %d", w.Code)
	}
}

func TestApp_KnownSessionProxies(t *testing.T) {
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

	registerApp("terminal/test-proxy-session", fakePort)
	defer unregisterApp("terminal/test-proxy-session")

	req := httptest.NewRequest("GET", "/app/terminal/test-proxy-session/", nil)
	w := httptest.NewRecorder()
	handleApp(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("proxy to fake ttyd: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "fake ttyd response") {
		t.Errorf("proxy did not forward to fake ttyd, got: %s", w.Body.String())
	}
}

func TestApp_RegisteredAppProxies(t *testing.T) {
	fakeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fake app response"))
	})
	fakeApp := httptest.NewServer(fakeHandler)
	defer fakeApp.Close()

	fakeAddr := fakeApp.Listener.Addr().String()
	fakePort := 0
	fmt.Sscanf(fakeAddr, "127.0.0.1:%d", &fakePort)
	if fakePort == 0 {
		fmt.Sscanf(fakeAddr, "[::1]:%d", &fakePort)
	}
	if fakePort == 0 {
		t.Fatalf("cannot parse port from test server addr: %s", fakeAddr)
	}

	registerApp("grafana", fakePort)
	defer unregisterApp("grafana")

	req := httptest.NewRequest("GET", "/app/grafana/", nil)
	w := httptest.NewRecorder()
	handleApp(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("proxy to fake app: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "fake app response") {
		t.Errorf("proxy did not forward to fake app, got: %s", w.Body.String())
	}
}
