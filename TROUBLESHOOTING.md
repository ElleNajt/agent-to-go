# Troubleshooting

**"open terminal failed: not a terminal"**

This happens when tmux can't allocate a TTY. Make sure you're running from an interactive terminal, not a script or SSH without `-t`.

**macOS firewall blocking ttyd**

Add ttyd to allowed apps: System Settings -> Network -> Firewall -> Options -> Add `/opt/homebrew/bin/ttyd`.

**Sessions not showing**

- Make sure tmux sessions exist: `tmux list-sessions`
- Check that you're using the alias so commands run through `agent-tmux`

**ttyd not connecting**

- Check ttyd is running: `ps aux | grep ttyd`
- Verify it's bound to localhost (127.0.0.1) — all access goes through the reverse proxy on :8090
- Clear stale tmux sockets if needed: `rm -rf /tmp/tmux-*` then retry

**"server exited unexpectedly" from tmux**

Clear stale tmux sockets:

```bash
rm -rf /tmp/tmux-*
```
