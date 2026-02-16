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
  |-- GET  /              Index page (lists sessions, renders CSRF token)
  |-- POST /connect/{s}   Start ttyd for session, serve auth bridge
  |-- POST /spawn         Create new tmux session + ttyd
  |-- POST /spawn-project Same, resolved from existing project
  |-- POST /kill/{s}      Kill a tmux session
  |
  v
ttyd :7700+ (one per active session, bound to Tailscale IP)
  |
  | WebSocket + basic auth
  |
  v
tmux session (persistent terminal)
```

## Security layers

### 1. Network binding (primary boundary)

The Go server and all ttyd instances bind exclusively to the Tailscale IP. If Tailscale is unavailable, the server refuses to start (`log.Fatal`). This is the main security boundary.

**Not protected against:** A compromised process on the same machine can reach the Tailscale IP via localhost routing.

### 2. CSRF protection

All state-changing endpoints (connect, spawn, kill) require a POST with a valid CSRF token. The token is:
- 32 bytes from `crypto/rand`, hex-encoded (256 bits of entropy)
- Compared with `subtle.ConstantTimeCompare` (timing-safe)
- Delivered only in hidden form fields, never in URLs
- Generated once at startup (acceptable for single-user service)

This prevents cross-origin attacks where a malicious website tries to submit forms to your agent-to-go instance.

### 3. Origin validation

POST requests are checked against the Tailscale IP origin. Cross-origin requests (from `evil.com`, `null`, etc.) are rejected.

The origin is matched against the exact Tailscale IP with boundary checking — the character after the IP must be `:` (port), `/` (path), or end-of-string. This prevents prefix attacks where `http://100.1.2.3.evil.com` would match a Tailscale IP of `100.1.2.3`.

**Limitation:** When both `Origin` and `Referer` headers are absent, the request is allowed. This is necessary because same-origin browser requests sometimes omit both. It means non-browser HTTP clients on the Tailnet can bypass origin validation. This is by design — origin validation protects against browser-based cross-origin attacks only, not against arbitrary network access (which is Tailscale's job).

### 4. Session name validation

Session names in `/connect/` and `/kill/` are validated against the actual list of tmux sessions. Only exact matches are accepted. Since session names are passed to `exec.Command` (not a shell), command injection via session names is not possible even without this validation — but the validation provides defense in depth.

### 5. Command and directory allowlists

The spawn endpoints require commands and directories to be in an explicit allowlist (`~/.config/agent-to-go/config.yaml`). If no config file exists, spawn is entirely disabled.

- **Commands:** Exact string match. `"bash -c evil"` does not match `"bash"`.
- **Directories:** Resolved to absolute paths with symlinks followed (`filepath.EvalSymlinks`). Path traversal via `../` is normalized before checking. Symlinks inside allowed directories that point outside are rejected.

### 6. ttyd per-session auth

Each ttyd instance gets a random password (16 bytes from `crypto/rand`, 128 bits). ttyd is started with:
- `-c t:PASSWORD` — basic auth required
- `-O` — origin header checking (rejects cross-origin WebSocket connections)
- `-i TAILSCALE_IP` — bound to Tailscale interface only

The auth bridge page uses `window.location.replace()` to navigate to ttyd, which avoids leaving the credentialed URL in browser history. `Referrer-Policy: no-referrer` prevents credential leakage via Referer headers.

**Limitation:** The `user:password@host` URL format is the only way to pass credentials for basic auth without a browser prompt. Some browsers may still expose this in the address bar or through extensions. The password is per-session and random, limiting the blast radius.

### 7. Argument injection prevention

All `tmux` and `ttyd` commands use `exec.Command` (no shell invocation) and include `--` before user-influenced arguments to prevent flag injection.

## Known limitations and accepted risks

### Tailnet access = full access

There is no authentication layer within the Tailnet. The CSRF token and origin validation protect against cross-origin browser attacks only. A script running on any Tailnet device can load the index page (getting the CSRF token) and then call any endpoint. This is the intended security model — Tailscale is the auth boundary.

### Error messages

All error responses return generic messages (`"access denied"`, `"failed to start terminal"`, etc.). Detailed error information is logged server-side only. This prevents information disclosure about allowlist contents, internal paths, and system configuration.

### Cleanup goroutine holds mutex during Kill+Wait

The orphaned ttyd cleanup goroutine (`cleanupOrphanedTtyd`) calls `Process.Kill()` then `cmd.Wait()` while holding `portMutex`. Since `Kill` sends SIGKILL, `Wait` returns promptly. If it didn't (kernel bug, zombie process issues), it would block all `startTtyd` calls. In practice this hasn't been an issue.

### Port reuse

When a ttyd instance exits, its port is reclaimed for future sessions. Each new session gets a fresh random password, so stale credentials from a previous session won't authenticate to the new one.

### tmux runs commands through sh -c

When `spawnSession` calls `tmux new-session ... -- cmd`, tmux passes `cmd` through `sh -c`. Since the command is validated against an exact-match allowlist containing only simple command names, this is not exploitable. But if the allowlist were to contain a command name with shell metacharacters, tmux would interpret them.

### Catch-all route

`http.HandleFunc("/", handleIndex)` makes the index page a catch-all — any unmatched path returns the full index page. This means there are no 404 responses. This is harmless since the index page is read-only, but it also means any path serves the CSRF token. If `net/http/pprof` were ever imported (even transitively), its `init()` would register debug handlers on `DefaultServeMux`, exposing heap profiles and goroutine dumps. Currently safe since pprof is not imported.

### Password in JavaScript context

The auth bridge page renders the ttyd password inside a `<script>` tag using `html/template`. Since passwords are hex-encoded (`[0-9a-f]` only), there's no risk of JavaScript injection. If the password format ever changed to include characters like `"`, `\`, or `</`, this would need JS-specific escaping.

### DNS rebinding

An attacker using DNS rebinding can make requests to your server from their JavaScript (by rebinding their domain to your Tailscale IP). They can read the index page and extract the CSRF token. However, the `Origin` header will still show the attacker's domain, so POST requests are blocked by origin validation. The combination of CSRF + origin check holds against DNS rebinding.

### Readiness poll holds mutex

The `startTtyd` readiness loop (polling TCP for up to 2 seconds) runs while holding `portMutex`. This blocks other `startTtyd` calls and the cleanup goroutine during the poll. In practice this causes at most 2 seconds of contention per ttyd startup, which is acceptable for a single-user service.

## Test coverage

The test suite (`main_test.go`) includes:

- **Security property tests:** CSRF required on all endpoints, constant-time comparison, origin rejection, POST-only enforcement, session validation
- **Attack simulations:** Cross-site reverse shell, IP spray, hidden form CSRF, img tag GET, clickjacking, DNS rebinding, session kill DoS, stolen CSRF + wrong origin, null origin, WebSocket hijacking, origin IP prefix attack
- **Allowlist tests:** Command/directory rejection, subdirectory allowance, path traversal blocking, reverse shell blocking, spawn-disabled-without-config, symlink bypass prevention
- **Origin validation:** Exact IP boundary checking, prefix attack rejection, port and path suffixes
