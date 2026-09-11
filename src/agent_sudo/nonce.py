"""Nonce generation and replay tracking.

The nonce is the *sole* basis of trust correlating "a human approved this
specific command" with "sudo is asking for a credential right now" — it is
generated once by the wrapper and reused, via AGENT_SUDO_NONCE, by the
askpass helper. Deliberately not PID/parent-process based: that's a known
spoofable weakness in prior art (see README). PID is logged for audit only,
never for authorization.

This module is intentionally asyncio-free so it's trivial to unit test.
Daemon-side pending-request bookkeeping (which needs asyncio primitives to
let a socket handler block on a verdict) lives in daemon.py and uses
ReplayGuard from here for the "already resolved" half of the picture.
"""

from __future__ import annotations

import secrets
from collections import OrderedDict

NONCE_BYTES = 32
RESOLVED_HISTORY_SIZE = 256


def generate() -> str:
    return secrets.token_urlsafe(NONCE_BYTES)


class ReplayGuard:
    """Bounded LRU of resolved nonces, so a replay gets an explicit
    'nonce_reuse' diagnostic instead of an ambiguous 'unknown nonce'."""

    def __init__(self, max_size: int = RESOLVED_HISTORY_SIZE):
        self._max_size = max_size
        self._resolved: OrderedDict[str, None] = OrderedDict()

    def mark_resolved(self, nonce: str) -> None:
        self._resolved[nonce] = None
        self._resolved.move_to_end(nonce)
        while len(self._resolved) > self._max_size:
            self._resolved.popitem(last=False)

    def was_resolved(self, nonce: str) -> bool:
        return nonce in self._resolved
