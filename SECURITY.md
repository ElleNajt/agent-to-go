# Security Model

## Threat model

agent-to-go gives your phone browser full terminal access to your computer. The security boundary is your Tailnet: **anyone who can reach your Tailscale IP gets full terminal access**. There is no authentication beyond Tailnet membership.

This means:
- Don't use this on a shared Tailnet
- Consider running on a dedicated coding VM rather than a machine with important secrets
- If your Tailscale key is compromised, your terminals are exposed

## Architecture

```
Phone (browser)
  |
  | HTTP over WireGuard (Tailscale)
  |
  v
agent-to-go :8090 (bound to Tailscale IP only)
  |
  |-- GET  /                 Index page (lists sessions, renders CSRF token)
  |-- POST /connect/{s}      Start ttyd, redirect to /terminal/{s}/
  |-- GET  /terminal/{s}/*   Reverse proxy to ttyd (HTTP + WebSocket)
  |-- POST /spawn            Create new tmux session + ttyd
  |-- POST /spawn-project    Same, resolved from existing project
  |-- POST /kill/{s}         Kill a tmux session
  |
  | reverse proxy (Host header validated)
  |
  v
ttyd :7700+ (one per active session, bound to 127.0.0.1 only)
  |
  | WebSocket
  |
  v
tmux session (persistent terminal)
```

## Security layers

### 1. Network binding (primary boundary)

The Go server binds exclusively to the Tailscale IP. ttyd instances bind to `127.0.0.1` (localhost only), making them unreachable from the network — all access goes through the reverse proxy. If Tailscale is unavailable, the server refuses to start (`log.Fatal`). This is the main security boundary.

### 2. CSRF protection

All state-changing endpoints (connect, spawn, kill) require a POST with a valid CSRF token. The token is:
- 32 bytes from `crypto/rand`, hex-encoded (256 bits of entropy)
- Compared with `subtle.ConstantTimeCompare` (timing-safe)
- Delivered only in hidden form fields, never in URLs
- Generated once at startup (acceptable for single-user service)

This prevents cross-origin attacks where a malicious website tries to submit forms to your agent-to-go instance.

### 3. Host header validation (DNS rebinding defense)

All requests pass through a middleware that validates the `Host` header matches the Tailscale IP. This blocks DNS rebinding attacks: after an attacker rebinds their domain to your IP, the browser sends `Host: evil.com` — which is rejected before any handler runs. The attacker can never read the index page or extract the CSRF token.

### 4. Origin validation

POST requests are checked against the Tailscale IP origin. Cross-origin requests (from `evil.com`, `null`, etc.) are rejected.

The origin is matched against the exact Tailscale IP with boundary checking — the character after the IP must be `:` (port), `/` (path), or end-of-string. This prevents prefix attacks where `http://100.1.2.3.evil.com` would match a Tailscale IP of `100.1.2.3`.

**Limitation:** When both `Origin` and `Referer` headers are absent, the request is allowed. This is necessary because same-origin browser requests sometimes omit both. It means non-browser HTTP clients on the Tailnet can bypass origin validation. This is by design — origin validation protects against browser-based cross-origin attacks only, not against arbitrary network access (which is Tailscale's job).

### 5. Session name validation

Session names in `/connect/` and `/kill/` are validated against the actual list of tmux sessions. Only exact matches are accepted. Since session names are passed to `exec.Command` (not a shell), command injection via session names is not possible even without this validation — but the validation provides defense in depth.

### 6. Command and directory allowlists

The spawn endpoints require commands and directories to be in an explicit allowlist (`~/.config/agent-to-go/config.yaml`). If no config file exists, spawn is entirely disabled.

- **Commands:** Exact string match. `"bash -c evil"` does not match `"bash"`.
- **Directories:** Resolved to absolute paths with symlinks followed (`filepath.EvalSymlinks`). Path traversal via `../` is normalized before checking. Symlinks inside allowed directories that point outside are rejected.

### 7. Reverse proxy isolation

ttyd instances bind to `127.0.0.1` and are not directly reachable from the network. All browser traffic goes through the `/terminal/{session}/` reverse proxy, which inherits the Host header middleware (layer 3). This closes the DNS rebinding attack path against ttyd — an attacker who rebinds to the Tailscale IP cannot reach ttyd ports, and requests through the main server are rejected by Host validation.

The reverse proxy handles both regular HTTP requests and WebSocket upgrades (used by ttyd for terminal I/O).

### 8. Argument injection prevention

All `tmux` and `ttyd` commands use `exec.Command` (no shell invocation). The `tmux new-session` command uses `--` before the command argument to prevent flag injection. Session names passed to `tmux attach -t`, `tmux kill-session -t`, and `tmux show-environment -t` are not `--`-separated, but are validated against the real tmux session list first — only exact matches to existing sessions are accepted. Since session names are generated by `generateSessionName` (which always starts with an alphanumeric command name), they cannot start with `-`.

## Known limitations and accepted risks

### Tailnet access = full access

There is no authentication layer within the Tailnet. The CSRF token and origin validation protect against cross-origin browser attacks only. A script running on any Tailnet device can load the index page (getting the CSRF token) and then call any endpoint. This is the intended security model — Tailscale is the auth boundary.

### Error messages

All error responses return generic messages (`"access denied"`, `"failed to start terminal"`, etc.). Detailed error information is logged server-side only. This prevents information disclosure about allowlist contents, internal paths, and system configuration.

### Cleanup goroutine holds mutex during Kill+Wait

The orphaned ttyd cleanup goroutine (`cleanupOrphanedTtyd`) calls `Process.Kill()` then `cmd.Wait()` while holding `portMutex`. Since `Kill` sends SIGKILL, `Wait` returns promptly. If it didn't (kernel bug, zombie process issues), it would block all `startTtyd` calls. In practice this hasn't been an issue.

### tmux runs commands through sh -c

When `spawnSession` calls `tmux new-session ... -- cmd`, tmux passes `cmd` through `sh -c`. Since the command is validated against an exact-match allowlist containing only simple command names, this is not exploitable. But if the allowlist were to contain a command name with shell metacharacters, tmux would interpret them.

### Catch-all route

`http.HandleFunc("/", handleIndex)` makes the index page a catch-all — any unmatched path returns the full index page. This means there are no 404 responses. This is harmless since the index page is read-only, but it also means any path serves the CSRF token. If `net/http/pprof` were ever imported (even transitively), its `init()` would register debug handlers on `DefaultServeMux`, exposing heap profiles and goroutine dumps. Currently safe since pprof is not imported.

### DNS rebinding

DNS rebinding is blocked at two layers. First, Host header validation (layer 3) rejects requests where `Host` doesn't match the Tailscale IP — after rebinding, the browser sends `Host: evil.com`, which is rejected before any handler runs. Second, ttyd instances bind to `127.0.0.1` (layer 7), so even if Host validation were bypassed, the attacker cannot reach ttyd ports directly from the network. All terminal access must go through the reverse proxy on port 8090.

### Readiness poll holds mutex

The `startTtyd` readiness loop (polling TCP for up to 2 seconds) runs while holding `portMutex`. This blocks other `startTtyd` calls and the cleanup goroutine during the poll. In practice this causes at most 2 seconds of contention per ttyd startup, which is acceptable for a single-user service.

## Test coverage

The test suite (`main_test.go`) includes:

- **Security property tests:** CSRF required on all endpoints, constant-time comparison, origin rejection, POST-only enforcement, session validation
- **Attack simulations:** Cross-site reverse shell, IP spray, hidden form CSRF, img tag GET, clickjacking, DNS rebinding (POST and GET/read), session kill DoS, stolen CSRF + wrong origin, null origin, WebSocket hijacking, origin IP prefix attack
- **Allowlist tests:** Command/directory rejection, subdirectory allowance, path traversal blocking, reverse shell blocking, spawn-disabled-without-config, symlink bypass prevention
- **Origin validation:** Exact IP boundary checking, prefix attack rejection, port and path suffixes
- **Host validation:** Tailscale IP accepted (with/without port), evil domains rejected, localhost rejected, IP prefix domains rejected
