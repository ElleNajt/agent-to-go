# agent-to-go

A secure building block for accessing local services from your phone — Claude Code, Codex, Emacs, or anything that runs in a terminal.

An HTTP server, a reverse proxy, and layered defenses against browser-based attacks (CSRF, DNS rebinding, clickjacking, origin validation). Runs on your Tailnet. ~730 lines of Go. See [SECURITY.md](SECURITY.md) for the full threat model.

**Warning:** This gives your phone full terminal access to your computer through your Tailnet. Review the code and security model before trusting it, and please contact me if you find any issues. Consider running on a dedicated coding VM rather than a machine with important secrets until this has been thoroughly hardened.

<p>
<img src="image_on_phone.png" width="250" alt="Phone and computer showing the same Claude session">
<img src="image_on_computer.png" width="250" alt="Desktop view">
<img src="picker.png" width="250" alt="Session picker grouped by project">
</p>

## How it works

1. Alias your command to run inside tmux (e.g., `alias claude='agent-tmux claude'`)
2. Run `agent-to-go` on your server - it lists all tmux sessions on a web page
3. Open the picker from your phone and tap a session to connect
4. Full terminal in your phone browser - same session as your computer

## Requirements

- [tmux](https://github.com/tmux/tmux)
- [ttyd](https://github.com/tsl0922/ttyd)
- [Tailscale](https://tailscale.com) (for secure access from phone)
- Go (to build)

## Install

```bash
# Install dependencies
# macOS
brew install tmux ttyd tailscale

# NixOS
nix-shell -p tmux ttyd tailscale

# Ubuntu/Debian
apt install tmux
# ttyd: see https://github.com/tsl0922/ttyd#installation

# Build the server
go build -o agent-to-go .

# Copy agent-tmux to your PATH
cp agent-tmux ~/.local/bin/
chmod +x ~/.local/bin/agent-tmux
```

Make sure `~/.local/bin` is in your PATH. Add to `~/.bashrc` or `~/.zshrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Setup

### 1. Configure aliases

Add to your shell config (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
alias claude='agent-tmux claude'
alias codex='agent-tmux codex'
alias aider='agent-tmux aider'
# any other CLI tools you want phone access to
```

Now every `claude` command runs in a tmux session with a name like `claude-myproject-swift-oak`.

### 2. Start the server

Run on your server/computer (the machine where you run your CLI tools):

```bash
./agent-to-go
```

It binds to port 8090 on your Tailscale IP. You'll see output like:

```
agent-to-go running at: http://100.x.x.x:8090
```

### 3. Connect from phone

1. Make sure your phone is on Tailscale
2. Open `http://<tailscale-ip>:8090` in your phone browser
3. You'll see a list of tmux sessions
4. Tap a session to connect

## How agent-tmux works

When you run `agent-tmux claude`:

1. Generates a unique session name: `claude-<project>-<adjective>-<noun>`
2. Creates a new tmux session running your command
3. Attaches you to that session

If you're already inside tmux, it creates a detached session and switches to it.

## Security

**Assumptions:**

- **Single-user Tailnet** - Anyone on your Tailnet gets full terminal access. There's no authentication beyond "can reach the Tailscale IP". Don't use this if you share your Tailnet with others.
- **Tailscale is running** - The server refuses to start without it (fail-closed). Tailscale provides encryption (WireGuard) and network-level access control.
- **Dedicated VM recommended** - Run on a coding VM rather than your main machine. If anything goes wrong, the blast radius is limited to the VM — not your personal files, credentials, or keys. Tailscale ACLs can further restrict what the VM can access on your network.

**What's protected:**

- Server bound to Tailscale IP only (refuses to start if Tailscale unavailable)
- ttyd instances bound to localhost, accessed via reverse proxy
- CSRF tokens on all state-changing endpoints
- Host header validation blocks DNS rebinding attacks
- Origin validation blocks cross-origin POST requests
- Command/directory allowlists for spawning sessions
- Orphaned ttyd processes cleaned up automatically

See [SECURITY.md](SECURITY.md) for the full security model.

**What's NOT protected:**

- No auth within Tailnet (Tailnet access = full terminal access)
- No HTTPS (relies on Tailscale's WireGuard encryption)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Your Computer                             │
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   tmux      │     │   tmux      │     │   tmux      │       │
│  │  session 1  │     │  session 2  │     │  session 3  │       │
│  │ (claude)    │     │ (claude)    │     │ (aider)     │       │
│  └──────▲──────┘     └──────▲──────┘     └─────────────┘       │
│         │                   │                                   │
│         │ attach            │ attach                            │
│         │                   │                                   │
│  ┌──────┴──────┐     ┌──────┴──────┐                           │
│  │    ttyd     │     │    ttyd     │  (spawned on demand)      │
│  │  127.0.0.1  │     │  127.0.0.1  │  (localhost only)        │
│  └──────▲──────┘     └──────▲──────┘                           │
│         │                   │                                   │
│         └────────┬──────────┘                                   │
│                  │ reverse proxy                                │
│           ┌──────┴──────┐                                       │
│           │ agent-to-go │  HTTP server                          │
│           │    :8090    │  - lists sessions                     │
│           │             │  - reverse proxies ttyd               │
│           └──────▲──────┘  - Host header validation             │
│                  │                                              │
│                  │ bound to Tailscale IP only                   │
└──────────────────┼──────────────────────────────────────────────┘
                   │
                   │ WireGuard encrypted tunnel
                   │
┌──────────────────┼──────────────────────────────────────────────┐
│    Tailscale     │                                              │
│    Network       │                                              │
└──────────────────┼──────────────────────────────────────────────┘
                   │
                   │
            ┌──────┴──────┐
            │   Phone     │
            │  (browser)  │
            └─────────────┘
```

| Component | Role |
|-----------|------|
| **tmux** | Persistent terminal sessions that survive disconnects |
| **ttyd** | Web server that exposes a terminal in a browser |
| **agent-to-go** | Glue: lists sessions, spawns ttyd, handles routing |
| **Tailscale** | Encrypted network, access control (only your devices) |
| **agent-tmux** | Wrapper to create uniquely-named tmux sessions |

## Vision

agent-to-go is the secure transport layer. Its job is: serve something to your phone securely over Tailscale. Right now that something is a raw terminal via ttyd, but ttyd is just one backend. You could build mobile-friendly ACP CLI frontends — a web UI with approve/reject buttons, a dashboard, a log viewer — and serve them through the same security layer. These could mirror state with other ACP frontends (e.g. agent-shell, Toad). agent-to-go handles the glue to the phone.

## See also

Similar tools for accessing terminal sessions remotely:

- [agentboard](https://github.com/gbasin/agentboard) — Agent status detection, log matching, remote SSH, mobile-optimized UI
- [247-claude-code-remote](https://github.com/QuivrHQ/247-claude-code-remote) — Push notifications, Claude/Codex hooks, cloud VM deployment
- [VibeTunnel](https://github.com/amantus-ai/vibetunnel) — File browser, Monaco editor, git integration, native iOS/macOS apps, session recording

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## License

MIT
