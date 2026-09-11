# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Human-approval-gated `sudo` for AI coding agents: an agent-side wrapper (`agent-sudo <cmd>`) blocks on an explicit approval verdict from a standing daemon running in a second terminal session the agent never touches, before ever invoking `sudo`. Full design rationale, prior-art comparison, and the sudo-rs finding: README.md.

## Commands

Install (editable, with dev deps):

    pip install -e ".[dev]"

Run tests (all ~1s, no real sudo/terminal/TOTP app needed -- see Architecture):

    python -m pytest
    python -m pytest tests/test_totp.py::test_rejects_replay_of_same_code   # single test

Lint (must stay at 10.00/10 -- see pyproject.toml's `[tool.pylint]` section for which checks are disabled project-wide and why, e.g. missing-function-docstring):

    pylint src/agent_sudo scripts/enroll_totp.py tests

Run the daemon (separate terminal, human-controlled -- never start this programmatically):

    agent-sudo-daemon                              # relay mode (default)
    agent-sudo-daemon --credential-mode=timestamp  # requires classic sudo, not sudo-rs

Preflight checks (mode-aware):

    agent-sudo doctor
    agent-sudo doctor --credential-mode=timestamp

Enroll TOTP (`timestamp` mode only -- `relay` mode needs no enrollment):

    python scripts/enroll_totp.py

The `agent-sudo`, `agent-sudo-askpass`, `agent-sudo-daemon` console scripts are symlinked into `~/.local/bin` on this machine so any process resolves them on PATH without activating the venv.

## Architecture

Three processes, one Unix domain socket (`~/.agent-sudo/agent-sudo.sock`, 0600), one wire protocol (newline-delimited JSON, `protocol.py`).

- **`cli.py`** (`agent-sudo` entrypoint) -- the only thing an agent invokes. Generates a nonce, sends a `request` to the daemon, and *blocks for an explicit approve verdict before ever invoking `sudo`*. There is no fallback path to a bare `sudo <cmd>` on any failure (daemon unreachable, deny, timeout) -- that invariant is the whole point of the tool and should never be weakened.
- **`daemon.py`** -- run by a human in a second terminal. A single serial `asyncio.Queue`-backed approval worker processes one request at a time; each `PendingRequest` wraps the original `protocol.RequestMsg` plus an `asyncio.Future` that the connection handler awaits and the worker resolves. Two credential-release modes, chosen via `--credential-mode`:
  - **`relay`** (default): the human types their real sudo password as the approval action itself (masked via `getpass`, no TOTP). Validated live (`sudo -k -S -v`), held in memory only long enough to answer one `askpass_query` for that nonce, never written to disk. This is the only mode that works when the system's `sudo` is **sudo-rs** (Ubuntu's Rust reimplementation) -- verified empirically that sudo-rs 0.2.13 rejects `tty_tickets`/`timestamp_type` outright (`visudo -c` gives a hard syntax error, not a warning), and the changelog shows no `global` timestamp option on any version. Check `sudo --version` before assuming a machine can use `timestamp` mode.
  - **`timestamp`** (classic sudo only, requires `Defaults !tty_tickets` in sudoers): TOTP-gated; on success the daemon runs `sudo -v` in its own session, never transmitting a password. The askpass helper is a fail-closed safety net in this mode -- its invocation at all signals the two-phase approval didn't suppress sudo's own prompt.
  - **Known, accepted (not mitigated) limitation of `relay` mode** -- see daemon.py's module docstring for the full writeup: anything holding an *approved* nonce can fetch the plaintext password directly from `_handle_askpass_query` by speaking the protocol, bypassing `askpass.py` entirely, since the agent always holds the nonce for every command it runs. The documented mitigation, not implemented, is a kernel-verified `SO_PEERCRED` ancestry check on that connection.
- **`askpass.py`** (`SUDO_ASKPASS` target) -- behavior is entirely dictated by the daemon's `credential_mode`; it just relays whatever verdict comes back over the socket for the nonce in `AGENT_SUDO_NONCE`.

`nonce.py`'s nonce is the *sole* correlation mechanism between "a human approved this" and "sudo is asking right now" -- deliberately not PID/parent-process-based (a known-spoofable weakness in prior art the README documents). `doctor.py` runs environment/sudoers preflight checks, mode-aware via `build_checks()`.

`tests/test_daemon_e2e.py` drives a *real* `Daemon` over a *real* Unix socket with a scripted human (the `scripted_input()` factory, feeding pre-computed TOTP codes or passwords) instead of a live one or a real `sudo` install -- this is how the approval logic gets exercised without a terminal. `sudo_cache.refresh_timestamp`/`validate_password` and the daemon's `input_reader`/`password_reader`/`now` are all injected specifically to make this possible. Tests marked `sudo_integration` require real sudo privileges and a TTY and are skipped by default.
