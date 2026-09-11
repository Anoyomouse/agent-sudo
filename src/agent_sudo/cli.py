# SPDX-License-Identifier: MIT
"""`agent-sudo <cmd...>` -- the only entrypoint the agent calls.

Two-phase flow: block for an explicit approve verdict from the daemon
*before* ever invoking sudo. There is no code path here that falls through
to a bare `sudo <cmd>` if the daemon is unreachable, denies, or times out.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import time
from pathlib import Path

from . import doctor
from . import nonce as nonce_mod
from . import paths, protocol
from .errors import DaemonUnreachable, ProtocolError, TimedOut

# Should exceed the daemon's own TTL (default 120s) with margin for connection
# setup and the round trip -- the daemon owns timeout resolution; this is a
# belt-and-suspenders guard against a daemon that itself hangs.
DEFAULT_CLIENT_TIMEOUT = 130.0


def send_request(sock_path: Path, msg: protocol.RequestMsg, timeout: float) -> protocol.Message:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect(str(sock_path))
        except OSError as exc:
            raise DaemonUnreachable(f"cannot reach approval daemon at {sock_path}: {exc}") from exc

        try:
            sock.sendall(protocol.encode_message(msg))
            reply_bytes = protocol.read_frame(sock)
        except socket.timeout as exc:
            raise TimedOut() from exc
        except OSError as exc:
            raise DaemonUnreachable(str(exc)) from exc
    finally:
        sock.close()

    if not reply_bytes:
        raise DaemonUnreachable("connection closed before a reply was received")
    return protocol.decode_message(reply_bytes)


def _askpass_entrypoint_path() -> str:
    resolved = shutil.which("agent-sudo-askpass")
    if not resolved:
        print(
            "agent-sudo: agent-sudo-askpass not found on PATH -- install the package "
            "(pip install -e .) so its console scripts are available",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return resolved


def main() -> None:
    command = sys.argv[1:]
    if not command:
        print("usage: agent-sudo <command> [args...]", file=sys.stderr)
        raise SystemExit(2)

    if command[0] == "doctor":
        doctor.main(command[1:])
        return

    request_nonce = nonce_mod.generate()
    request = protocol.RequestMsg(
        nonce=request_nonce,
        pid=os.getpid(),
        uid=os.getuid(),
        cwd=os.getcwd(),
        command=command,
    )

    try:
        verdict = send_request(paths.socket_path(), request, timeout=DEFAULT_CLIENT_TIMEOUT)
    except DaemonUnreachable as exc:
        print(
            f"agent-sudo: approval daemon not running or unreachable ({exc}) -- "
            f"refusing to run {' '.join(command)!r}",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    except TimedOut as exc:
        print("agent-sudo: timed out waiting for a verdict -- refusing to run", file=sys.stderr)
        raise SystemExit(1) from exc
    except ProtocolError as exc:
        print(f"agent-sudo: malformed response from daemon ({exc}) -- refusing to run", file=sys.stderr)
        raise SystemExit(1) from exc

    if not isinstance(verdict, protocol.VerdictMsg) or verdict.nonce != request_nonce:
        print("agent-sudo: unexpected or mismatched response from daemon -- refusing to run", file=sys.stderr)
        raise SystemExit(1)

    if verdict.result != "approve":
        print(f"agent-sudo: request denied ({verdict.reason}) -- refusing to run", file=sys.stderr)
        raise SystemExit(1)

    if verdict.expires_at is not None and time.time() >= verdict.expires_at:
        print("agent-sudo: approval already expired -- refusing to run", file=sys.stderr)
        raise SystemExit(1)

    env = os.environ.copy()
    env["SUDO_ASKPASS"] = _askpass_entrypoint_path()
    env["AGENT_SUDO_NONCE"] = request_nonce

    # Expected to succeed via the timestamp cache the daemon just refreshed,
    # without sudo ever invoking the askpass helper.
    os.execvpe("sudo", ["sudo", "-A", *command], env)


if __name__ == "__main__":
    main()
