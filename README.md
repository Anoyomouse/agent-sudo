# agent-sudo

Let an AI coding agent (Claude Code, Cursor, etc.) run `sudo` commands, gated on a human's explicit, out-of-band approval — without giving the agent passwordless sudo, and without relying on a GUI dialog.

## Problem

Coding agents increasingly need to run privileged commands, but sudo has no TTY to prompt in when invoked from an agent. The usual workarounds are:

- **Passwordless sudo (`NOPASSWD`)** — simplest, but removes the human from the loop entirely for whatever's in the sudoers rule.
- **`SUDO_ASKPASS` + GUI dialog** — sudo calls a helper program that pops a dialog (zenity/kdialog/AppleScript) and prints the password to stdout on approval. Works, but requires a graphical session and ties "a human approved this" to "this process can draw a window."
- **`SUDO_ASKPASS` + inline TOTP** — same mechanism, but the helper asks for a 6-digit code instead of/alongside the password, entered synchronously in the same invocation.

None of these decouple "a human is actively watching and approving" from "this process happens to have terminal/GUI access." That's the gap this project targets: a **standing approval daemon running in a second terminal session**, which the askpass helper talks to over a local socket. The daemon shows the actual command being requested before releasing anything — so approval works identically over SSH, in a headless environment, or on a desktop, and the human's "yes" always happens in a session the agent never touches.

## Prior art

| Project | Approval UI | Password storage | Second-session daemon? |
|---|---|---|---|
| [sudoplz](https://github.com/crypdick/sudoplz) | GUI dialog (zenity/AppleScript) by default; TOTP as a headless fallback | SSH-key-encrypted (age/OpenSSL), cached ~1 week, plus path + parent-process whitelist and rate limiting | No — TOTP is entered synchronously inside the same askpass invocation |
| [secure-askpass](https://github.com/GlassOnTin/secure-askpass) | TOTP code, entered inline or via env var | Same SSH-key-encryption scheme as sudoplz (related lineage) | No — single-process askpass, no socket/daemon |
| [claude-sudo-askpass](https://github.com/dgutson/claude-sudo-askpass) | GUI dialog only (zenity/kdialog) | Not persisted — password flows straight from dialog to sudo; relies on sudo's own ~15 min timestamp cache | No — GUI-only, no SSH/terminal-only mode |
| [AgentSudo](https://github.com/topics/askpass) | Slack message approval | N/A — general agent permission system, not actually sudo/askpass | No — different domain |
| [anthropics/claude-code#1135](https://github.com/anthropics/claude-code/issues/1135) | GUI dialog + SSH-key encryption (same lineage as above) | Same | No — closed "not planned" |

Known weaknesses flagged in that closed issue, worth designing around: GUI/prompt spoofing, parent-process-only verification being easy to spoof, and predictable temp file paths for the decrypted password.

## Architecture

```
 agent               approval daemon (2nd terminal/session)
   │                          │
   │  agent-sudo <cmd>        │  listens on ~/.agent-sudo/agent-sudo.sock
   │────────────┐             │  (unix socket, user-owned, 0600)
   │            │             │
   │   1. generate nonce      │
   │   2. send {cmd, cwd,     │
   │      nonce} over socket ─┼──▶ shows request, waits for the human's approval
   │            │             │
   │  (blocks for a verdict — no sudo call yet)
   │            │             │
   │            │             ◀── human approves (or denies/times out)
   │  3. exec sudo -A cmd     │
   │      SUDO_ASKPASS=helper │
   │      AGENT_SUDO_NONCE    │
   │            │             │
   │  askpass helper connects │
   │  to socket, sends nonce, ┼──▶ credential-mode dependent: "relay" hands back
   │  blocks for verdict   ◀──┼    the password relayed for that nonce; "timestamp"
   │            │             │    always denies (safety net, see below)
   ▼            ▼             ▼
 sudo runs the command (or fails closed on timeout/deny/bad credential)
```

The wrapper never invokes `sudo` until it has an explicit `approve` verdict from the daemon — there is no code path that falls through to a bare `sudo <cmd>` if the daemon is unreachable, denies, or times out.

## Credential release modes

Two modes, picked at daemon startup (`agent-sudo-daemon --credential-mode=relay|timestamp`, and `agent-sudo doctor --credential-mode=...` for the matching preflight checks). **`relay` is the default.**

### `relay` (default)

The human's approval action *is* typing their real sudo password, directly into the daemon's own terminal (masked, via `getpass`) — no separate second factor. The daemon validates it live (`sudo -k -S -v`, never riding an existing cache), holds it in memory only long enough to answer one `askpass_query` for that specific nonce, and never writes it to disk. The askpass helper is the actual credential path in this mode, not a fallback.

This is the only mode that works if your system's `sudo` is [**sudo-rs**](https://github.com/trifectatechfoundation/sudo-rs) (Ubuntu's Rust reimplementation, increasingly the default `/usr/bin/sudo` via `update-alternatives` — check with `sudo --version`). See "sudo-rs incompatibility" below for why `timestamp` mode can't be made to work there at all.

**Known limitation, accepted rather than mitigated in this build:** whoever holds an *approved* nonce can get the plaintext password back by speaking the wire protocol directly to the daemon — they don't need to go through the real `askpass.py`/`sudo -A` at all. The agent always holds the nonce for every command it runs (it generates it), so a malicious or compromised agent doesn't need to race anything: it can skip the wrapper, query the socket itself, and walk away with a real, reusable password instead of running one approved command. That's a materially bigger blast radius than `timestamp` mode, where nothing reusable ever left the daemon.

The effective fix — **not implemented here** — is a kernel-verified process-ancestry check on the `askpass_query` connection (`SO_PEERCRED`, confirming the connecting process actually descends from the original wrapper's PID, rather than trusting the self-reported `pid` field in the message). That raises the bar a lot: a thief would have to actually drive a real `sudo -A` child through the real exec chain, which immediately consumes the password for that one real command, instead of just opening a socket and asking. It would not make theft cryptographically impossible against an agent with arbitrary code execution. Note that encrypting the relayed password with a nonce-derived key would *not* help here: the daemon does an exact-match dict lookup on the nonce before it ever touches the secret, so anyone without the exact nonce already gets `nonce_unknown` with no payload sent at all, and anyone who does have it could derive the same key.

The one mitigation that's actually kernel-enforced, not just protocol discipline, is **running the daemon as a separate OS user from the agent** — then the socket's `0600` ownership genuinely excludes the agent's UID from connecting at all. This build assumes (does not enforce) that the agent and the daemon share an OS user, matching the common single-user dev-box setup; `doctor` does not currently check for or require user separation.

Accept this if your threat model is "stop an LLM from running an unreviewed destructive command without a human glancing at it first." Treat it as insufficient if your threat model includes actively adversarial code trying to steal root.

### `timestamp` (requires classic sudo)

On approval, the daemon runs `sudo -v` in its own trusted session — if the human's timestamp isn't already fresh, *sudo itself* prompts for the real password right there, out-of-band from the agent entirely. No password ever transits the socket in this mode. Requires `Defaults !tty_tickets` (or `timestamp_type=global`) in sudoers so that timestamp is visible to the agent's separate session later; `agent-sudo doctor --credential-mode=timestamp` checks for this and prints the exact `visudo` command to add it. The askpass helper is wired up only as a fail-closed safety net in this mode — its invocation at all means the two-phase approval didn't suppress sudo's own prompt (race, or the sudoers prerequisite is missing), and it always denies rather than trying to authenticate a second way.

### sudo-rs incompatibility

Verified empirically on a machine running sudo-rs 0.2.13 (Ubuntu, via `update-alternatives`): `visudo -c` rejects both `tty_tickets` and `timestamp_type` outright as unknown settings — a hard parse error, not a warning. Checked the sudo-rs changelog too: even the newest sudo-rs only ever adds `timestamp_type=ppid` (binds the cache to the parent process); there's no `global` option on any version. That means `timestamp` mode cannot be made to work against sudo-rs at all, by design, not misconfiguration — `relay` mode is the only option there. sudo-rs does support `-A`/`SUDO_ASKPASS` normally, which is why `relay` mode works fine against it.

## Status

Implemented and tested (41 tests passing: protocol framing, nonce replay/expiry, TOTP verification, and a real-daemon-plus-socket end-to-end harness covering both credential modes with a scripted human instead of a live one).

```
src/agent_sudo/
├── cli.py            # `agent-sudo <cmd...>` wrapper, plus `agent-sudo doctor`
├── askpass.py         # SUDO_ASKPASS target
├── daemon.py          # approval daemon — both credential modes live here
├── doctor.py           # environment/sudoers preflight checks
├── protocol.py         # NDJSON wire format
├── nonce.py             # nonce generation + replay tracking
├── totp.py               # TOTP verification (timestamp mode only)
├── sudo_cache.py           # sudo -v / sudo -S -v wrappers for both modes
└── paths.py                 # ~/.agent-sudo/* resolution + permission handling
scripts/enroll_totp.py        # one-shot TOTP enrollment (timestamp mode only), QR via `qrcode`
tests/                          # pytest + pytest-asyncio, incl. test_daemon_e2e.py
```

Written in Python (chosen over Go for audit-friendliness and prototyping speed, per the original design tradeoff — a Go rewrite of the daemon/askpass helper remains worth revisiting before distributing this beyond a single machine).

Not yet done: the `SO_PEERCRED` ancestry check documented above as `relay` mode's real mitigation; a `doctor` check for agent/daemon OS-user separation; the manual two-terminal smoke test against a real human and real `sudo` (the automated suite covers the daemon's logic with a scripted human, but nothing yet exercises the real `sudo -A` / real askpass binary end-to-end).
