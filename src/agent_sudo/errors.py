# SPDX-License-Identifier: MIT
"""Exception hierarchy shared across the wrapper, askpass helper, and daemon."""


class AgentSudoError(Exception):
    """Base class for all agent-sudo errors."""


class DaemonUnreachable(AgentSudoError):
    """The approval daemon's socket could not be reached at all."""


class ProtocolError(AgentSudoError):
    """A message did not conform to the wire protocol (malformed, oversized, wrong version)."""


class Denied(AgentSudoError):
    """The daemon returned an explicit deny verdict."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"denied: {reason}")


class TimedOut(AgentSudoError):
    """No verdict arrived within the client-side timeout."""
