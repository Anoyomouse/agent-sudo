---
name: agent-sudo-onboarding
description: Use when a human asks to install agent-sudo, set up human-approval-gated sudo for an AI coding agent, or wants help understanding/running the agent-sudo daemon for the first time. Walks through installing the tool and teaches the human how the two-terminal approval flow works — this skill is for onboarding a person, not for running privileged commands yourself (see the agent-sudo skill for that).
---

# Installing agent-sudo and teaching a human to use it

This skill is for *setting up* [agent-sudo](https://github.com/Anoyomouse/agent-sudo) and
explaining it to the human at the keyboard — not for running privileged commands yourself (use
the `agent-sudo` skill for that once it's installed).

Do the install steps yourself. Do **not** start the daemon yourself at any point — that step is
always the human's, and explaining why is part of this skill's job.

## 1. Get the source and install it

```
git clone https://github.com/Anoyomouse/agent-sudo.git
cd agent-sudo
pip install -e ".[dev]"        # editable install + test/lint deps
```

Console scripts (`agent-sudo`, `agent-sudo-askpass`, `agent-sudo-daemon`) land in the active
environment's bin directory. If the human wants them available system-wide without activating a
venv, symlink them onto `PATH` (adjust the venv path to wherever it actually is):

```
mkdir -p ~/.local/bin
for f in agent-sudo agent-sudo-askpass agent-sudo-daemon; do
  ln -s "$(pwd)/.venv/bin/$f" ~/.local/bin/"$f"
done
```

Confirm `~/.local/bin` is on `PATH`, and sanity check:

```
agent-sudo --help
```

## 2. Figure out which credential mode applies

Check which `sudo` is actually installed — this decides the mode, it isn't a preference:

```
sudo --version
```

- If it reports **sudo-rs** (Ubuntu's Rust reimplementation — increasingly the default via
  `update-alternatives`): **`relay` mode only.** `timestamp` mode cannot work at all against
  sudo-rs (no `global`/`!tty_tickets`-equivalent exists in any sudo-rs version — verified against
  the changelog, and `visudo -c` hard-rejects the setting). Don't spend time trying to configure
  it.
- If it's **classic sudo**: either mode works. `relay` is still the default and is simpler to set
  up (no sudoers edit, no TOTP app); `timestamp` avoids the daemon ever seeing a real password,
  at the cost of a sudoers change and enrolling an authenticator app.

Tell the human which mode fits their `sudo`, and let them decide `relay` vs `timestamp` if both
are viable — don't pick `timestamp` for them unless they say they want the password kept fully
out of the daemon's process.

## 3. Mode-specific setup

**`relay` (default, no extra setup):** nothing further needed. The human's approval action *is*
typing their real sudo password into the daemon's own terminal when prompted.

**`timestamp` (classic sudo only):**

1. Enroll a TOTP secret (one-time, on the machine that will run the daemon):
   ```
   python scripts/enroll_totp.py
   ```
   This prints an otpauth:// URI / QR code — the human scans it into an authenticator app
   (Authy, Google Authenticator, 1Password, etc.). It refuses to overwrite an existing enrollment.
2. Add the sudoers prerequisite so the timestamp is visible outside the daemon's own TTY:
   ```
   agent-sudo doctor --credential-mode=timestamp
   ```
   This prints the exact `visudo` line to add (`Defaults !tty_tickets` or
   `Defaults timestamp_type=global`) if it's missing — have the human run `visudo` themselves
   rather than editing `/etc/sudoers` with a raw redirect.

## 4. Validate the setup

```
agent-sudo doctor                                  # relay mode
agent-sudo doctor --credential-mode=timestamp       # timestamp mode
```

Fix anything it flags before moving on — don't tell the human it's ready if `doctor` isn't clean.

## 5. Explain the two-terminal model to the human

This is the part people most often get wrong on first use, so be explicit:

- **The daemon runs in a second terminal session that the agent never touches.** That separation
  is the entire security property — it's what makes "a human approved this" mean something
  distinct from "some process has a TTY."
- The human starts it themselves, in a terminal they control:
  ```
  agent-sudo-daemon                                  # relay mode (default)
  agent-sudo-daemon --credential-mode=timestamp       # timestamp mode
  ```
- **Tell the human explicitly: never let an agent run this command for them, including this one.**
  If an agent could start the daemon, it could also approve its own requests — the whole design
  falls apart. Starting the daemon must always be a deliberate action the human takes in their own
  terminal.
- Once running, when an agent invokes `agent-sudo <cmd>`, the daemon prints the actual command
  requested (and cwd) and waits:
  - **relay:** the human types their real sudo password (masked) as the approval action.
  - **timestamp:** the human enters the current 6-digit code from their authenticator app.
- A denial, a timeout, or closing the daemon all mean the agent's command does not run — there is
  no fallback path to a bare `sudo` on the agent side by design.

## 6. Point them at the reference docs

For anything beyond the basics — the sudo-rs incompatibility details, the accepted
plaintext-password-in-relay-mode limitation and why it's accepted rather than fixed, prior-art
comparison — the human should read this repo's `README.md`. Don't re-explain all of that inline;
link them there.

## 7. Wire up the companion skill

If the human also wants their coding agent to *use* agent-sudo going forward (not just have it
installed), make sure the `agent-sudo` skill (sibling directory in `.claude/skills/`) is available
wherever they want that behavior — copy the whole `.claude/skills/` folder into a project, or into
`~/.claude/skills/` for it to apply everywhere. That skill is what actually routes future
privileged commands through `agent-sudo` instead of raw `sudo`; this one is just for getting to
that point.
