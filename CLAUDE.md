# agent-to-go

Phone-accessible terminal sessions via tmux + ttyd + Tailscale.

## Setup

1. Install dependencies: `tmux`, `ttyd`, `tailscale`
2. Build: `go build -o agent-to-go ./server/`
3. Add `~/code/agent-to-go` to PATH
4. Add alias: `alias claude='agent-tmux claude'`
5. Run `./agent-to-go` (requires Tailscale to be running)

## Architecture

- `server/` - Go source: HTTP server on tsnet (Tailscale TLS), filippo.io/csrf, ttyd reverse proxy
- `agent-tmux` - Bash script that creates uniquely-named tmux sessions

## Security model

- Single-user Tailnet assumed (no auth beyond Tailscale)
- Fails closed if Tailscale unavailable
- Session names validated against tmux to prevent injection
- See README.md Security section for full details
