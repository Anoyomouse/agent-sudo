---
name: agent-sudo
description: Use whenever a task needs to run a privileged/root command (sudo, apt install, systemctl, writing to a root-owned path, "permission denied" that needs root) on a machine that has agent-sudo installed. Routes privileged commands through the human-approval-gated agent-sudo wrapper instead of raw sudo. Trigger on any of: sudo, root access, privileged command, NOPASSWD, permission denied requiring elevation.
---

# agent-sudo: use it instead of raw sudo

This machine (or repo) has [agent-sudo](https://github.com/Anoyomouse/agent-sudo) installed: a
human-approval-gated wrapper around `sudo`. If a task needs to run a privileged command, use it
instead of calling `sudo` directly:

```
agent-sudo <command> [args...]
```

This blocks until a human explicitly approves the *exact* command from a separate terminal
session running `agent-sudo-daemon` — a daemon only the human starts and controls.

## Before using it

Confirm it's actually installed and on PATH:

```
which agent-sudo agent-sudo-daemon agent-sudo-askpass
```

If none of those resolve, agent-sudo isn't set up here — see the `agent-sudo-onboarding` skill
to install it and walk the human through setup. Don't fall back to raw `sudo` just because
agent-sudo is missing; ask the human how they want privileged commands handled on this machine.

## Rules

- **Never start `agent-sudo-daemon` yourself.** It must run in a session you never touch — that
  is the entire point of the tool (it's what lets "a human approved this" mean something). If a
  command fails with something like "approval daemon not running or unreachable," tell the human
  and ask them to start `agent-sudo-daemon` in a terminal of their own. Do not work around it.
- **Never fall back to raw `sudo`, `sudo -A` with your own askpass, or ask the human to set up
  `NOPASSWD`** if `agent-sudo` denies the request, times out, or the daemon is unreachable. All
  three are exactly the failure modes this tool exists to prevent falling through to. A denial or
  timeout means the answer is no for now, not "try another way."
- **Never read, print, or otherwise try to access the TOTP secret, the daemon's Unix socket, or
  the relayed password directly.** The nonce-based protocol is the only sanctioned path — see
  README.md's "Known limitation" note on why this matters even more in `relay` mode.
- If something seems misconfigured (permissions, sudoers prerequisites, wrong credential mode),
  run `agent-sudo doctor` (add `--credential-mode=timestamp` if that's the mode in use) rather
  than guessing or trying to patch around it yourself.
- If a privileged command genuinely can't go through `agent-sudo` (e.g. it needs interactive TTY
  behavior agent-sudo doesn't support), stop and ask the human how they want to handle it — don't
  silently choose a less-supervised path.

## Full reference

Design, both credential modes (`relay` vs `timestamp`), and known limitations: this project's
`README.md` and `CLAUDE.md` (wherever agent-sudo's source checkout lives on this machine — check
`pip show agent-sudo` or the symlink target of `agent-sudo` on PATH if you need to find it).
