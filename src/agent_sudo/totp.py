# SPDX-License-Identifier: MIT
"""TOTP secret provisioning and verification.

The secret lives only at paths.totp_secret_path() (0600, daemon-owned) and
must never be read by the agent-side wrapper/askpass — see doctor.py for the
best-effort check of that boundary. Verification is not just pyotp.verify():
we track the last-accepted time-step ourselves so a code can't be replayed a
second time within its own +-1 step tolerance window, and we rate-limit
consecutive failures.
"""

from __future__ import annotations

import hmac
import os
import time
from pathlib import Path

import pyotp

DEFAULT_INTERVAL = 30
DEFAULT_WINDOW = 1  # +-30s tolerance, matching typical authenticator app skew
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 30


def provision(path: Path, username: str = "user", issuer: str = "agent-sudo") -> tuple[str, str]:
    """Generate a new secret and write it to path (fails if path already exists).

    Returns (secret, otpauth_uri).
    """
    secret = pyotp.random_base32()
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret + "\n")
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    return secret, uri


def load_secret(path: Path) -> str:
    return path.read_text().strip()


class TotpVerifier:
    """Stateful verifier: one instance per daemon process lifetime.

    `now` is injectable so tests don't need to sleep 30s to test step
    boundaries.
    """

    def __init__(
        self,
        secret: str,
        *,
        interval: int = DEFAULT_INTERVAL,
        window: int = DEFAULT_WINDOW,
        max_failed_attempts: int = MAX_FAILED_ATTEMPTS,
        lockout_seconds: float = LOCKOUT_SECONDS,
        now=time.time,
    ):
        self._totp = pyotp.TOTP(secret, interval=interval)
        self._interval = interval
        self._window = window
        self._max_failed_attempts = max_failed_attempts
        self._lockout_seconds = lockout_seconds
        self._now = now

        self._last_accepted_step = -1
        self._failed_attempts = 0
        self._locked_until = 0.0

    def locked(self) -> bool:
        return self._now() < self._locked_until

    def verify(self, code: str) -> tuple[bool, str | None]:
        """Returns (accepted, failure_reason). failure_reason is one of
        'rate_limited' or 'invalid' when accepted is False."""
        if self.locked():
            return False, "rate_limited"
        if not code or not code.isdigit():
            self._record_failure()
            return False, "invalid"

        current_step = int(self._now() // self._interval)
        for offset in range(-self._window, self._window + 1):
            step = current_step + offset
            if step <= self._last_accepted_step:
                continue  # already used (or older than what we've used) -- replay guard
            candidate = self._totp.at(step * self._interval)
            if hmac.compare_digest(candidate, code):
                self._last_accepted_step = step
                self._failed_attempts = 0
                return True, None

        self._record_failure()
        return False, "invalid"

    def _record_failure(self) -> None:
        self._failed_attempts += 1
        if self._failed_attempts >= self._max_failed_attempts:
            self._locked_until = self._now() + self._lockout_seconds
            self._failed_attempts = 0
