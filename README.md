# agent-phone

Access terminal sessions from your phone's browser. Works with Claude Code, or any CLI tool.

## How it works

1. Alias your command to run inside tmux (e.g., `alias claude='agent-tmux claude'`)
2. A web picker lists all tmux sessions
3. Tap a session to connect via ttyd
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
brew install tmux ttyd

# NixOS
nix-shell -p tmux ttyd

# Ubuntu/Debian
apt install tmux ttyd

# Build the picker
go build -o agent-phone .

# Copy agent-tmux to your PATH
cp agent-tmux ~/.local/bin/  # or /usr/local/bin
```

## Usage

**Start the picker** (run on your server/computer):

```bash
./agent-phone
```

Opens on port 8090, bound to Tailscale IP only.

**Alias commands to always use tmux**:

Add to your shell config (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
alias claude='agent-tmux claude'
alias aider='agent-tmux aider'
# etc.
```

Now every `claude` command automatically runs in a tmux session with a name like `claude-myproject-swift-oak`.

**Connect from phone**:

Open `http://<tailscale-ip>:8090` in your phone browser. Tap a session to connect.

## Security

- Picker binds to Tailscale IP only - not accessible from public internet or local network
- Only devices on your Tailscale network can connect
- ttyd sessions spawned on ports 7700+

## Troubleshooting

**macOS firewall blocking ttyd**: Add `/opt/homebrew/bin/ttyd` to allowed apps in System Settings → Network → Firewall → Options.

**Sessions not showing**: Make sure you have the alias set up so commands run through `agent-tmux`.
