"""`agent-sudo-askpass` -- the SUDO_ASKPASS target.

Behavior depends on the daemon's credential_mode, transparently to this file
(it just relays whatever the daemon decides):

- "relay" (default): this IS the credential path. The daemon already
  validated a real sudo password the human typed as their approval action;
  this helper fetches it once for this nonce and hands it to sudo. See the
  KNOWN LIMITATION note in daemon.py's module docstring -- anything that
  knows an approved nonce can get the same password by skipping this helper
  and querying the daemon directly, which this file cannot detect or prevent.

- "timestamp": this should almost never actually be invoked -- the wrapper
  doesn't call `sudo -A` until the daemon has already refreshed sudo's
  timestamp cache via its own `sudo -v`. If sudo invokes this anyway, it
  means the two-phase approval didn't suppress the prompt (race, or the
  `!tty_tickets` sudoers prerequisite is missing, or you're on sudo-rs which
  doesn't support that prerequisite at all) -- treated as a fail-closed
  signal, not a second chance to authenticate.

sudo reads whatever this prints to stdout as the password. Printing nothing
and exiting non-zero makes sudo fail the credential check cleanly.
"""

from __future__ import annotations

import os
import socket
import sys

from . import paths, protocol
from .errors import DaemonUnreachable, ProtocolError

CONNECT_TIMEOUT = 10.0


def main() -> None:
    request_nonce = os.environ.get("AGENT_SUDO_NONCE")
    if not request_nonce:
        print(
            "agent-sudo-askpass: AGENT_SUDO_NONCE not set -- this helper is only "
            "meant to be invoked by sudo -A from within the agent-sudo wrapper",
            file=sys.stderr,
        )
        raise SystemExit(1)

    query = protocol.AskpassQueryMsg(nonce=request_nonce, pid=os.getpid())

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        try:
            sock.connect(str(paths.socket_path()))
            sock.sendall(protocol.encode_message(query))
            reply_bytes = protocol.read_frame(sock)
        except (OSError, socket.timeout) as exc:
            raise DaemonUnreachable(str(exc)) from exc
    finally:
        sock.close()

    if not reply_bytes:
        print("agent-sudo-askpass: daemon closed the connection without a reply -- denying", file=sys.stderr)
        raise SystemExit(1)

    try:
        reply = protocol.decode_message(reply_bytes)
    except ProtocolError as exc:
        print(f"agent-sudo-askpass: malformed reply from daemon ({exc}) -- denying", file=sys.stderr)
        raise SystemExit(1) from exc

    if not isinstance(reply, protocol.AskpassReplyMsg) or reply.result != "approve" or not reply.secret:
        reason = getattr(reply, "reason", None) or "denied"
        print(f"agent-sudo-askpass: {reason} -- refusing to supply a credential", file=sys.stderr)
        raise SystemExit(1)

    # Only reachable in Option A (password_cache) mode, which is not
    # implemented in this build -- see daemon.py.
    print(reply.secret)


if __name__ == "__main__":
    main()
