# SPDX-License-Identifier: MIT
"""sudo integration for both credential-release modes.

refresh_timestamp() is "timestamp" mode's mechanism: run in the daemon's own
trusted terminal session, it prompts for the real password right there
(out-of-band from the agent entirely) if the cache isn't already fresh.
Requires `Defaults !tty_tickets` (or `timestamp_type=global`) in sudoers for
the refreshed timestamp to be visible to the agent's separate session/tty
later — see doctor.py. NOTE: as of 0.2.x, sudo-rs (Ubuntu's Rust
reimplementation, increasingly the default `/usr/bin/sudo`) supports neither
setting at all -- `sudo -n -l` / `visudo -c` reject them outright as unknown
settings, which makes this mode structurally unusable there. Check
`sudo --version` if this mode's requests are mysteriously always denying.

validate_password() is "relay" mode's mechanism: perform a real, live
authentication check against a password the human just typed, without
touching the persistent timestamp cache at all (`-k` resets it first, so
this never rides an existing cache silently).

Both kept as thin, easily-monkeypatchable wrappers so tests never need a
real sudo installation.
"""

from __future__ import annotations

import subprocess


def refresh_timestamp() -> bool:
    result = subprocess.run(["sudo", "-v"], check=False)
    return result.returncode == 0


def validate_password(password: str) -> bool:
    result = subprocess.run(
        ["sudo", "-k", "-S", "-v"],
        input=password + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0
