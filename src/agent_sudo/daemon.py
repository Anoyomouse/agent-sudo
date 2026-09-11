# SPDX-License-Identifier: MIT
"""The approval daemon — run in a second terminal/session the agent never touches.

One serial approval worker processes queued requests one at a time (a human
approves one thing at a time by construction). Each pending request's
asyncio.Future is resolved by the worker and awaited by that request's own
connection handler, so no polling is needed.

Two credential-release modes:

- "relay" (default): the human types their real sudo password directly as
  the approval action (no TOTP -- the password itself is the proof of
  presence). The daemon validates it live via `sudo -k -S -v`, never writes
  it to disk, and relays it exactly once through the askpass helper for that
  one nonce. This is the only mode that works against sudo-rs (Ubuntu's Rust
  reimplementation), which has no `tty_tickets`/`timestamp_type` support at
  all as of 0.2.x -- see sudo_cache.py.

- "timestamp" ("Option B" from the design plan, requires classic sudo +
  `Defaults !tty_tickets`): on a valid TOTP code, the daemon runs `sudo -v`
  in its own session and never transmits a real password anywhere. The
  askpass helper is wired up only as a fail-closed safety net in this mode.

KNOWN LIMITATION of "relay" mode (accepted, not mitigated, in this build):
whoever holds an *approved* nonce can get the plaintext password back by
speaking the wire protocol directly to _handle_askpass_query -- they don't
need to go through the real askpass.py/sudo -A at all. The agent always
holds the nonce for every command it runs (it's the one that generates it),
so a malicious/compromised agent doesn't need to race anything: it can skip
the wrapper, query the socket itself, and walk away with a real, reusable
password instead of running one approved command. This is a materially
bigger blast radius than "timestamp" mode, where nothing reusable ever left
the daemon. The effective fix is a kernel-verified process-ancestry check on
the askpass_query connection (SO_PEERCRED, confirming it actually descends
from the original wrapper's PID rather than trusting the self-reported `pid`
field) -- NOT IMPLEMENTED here. Encrypting the relayed password with a
nonce-derived key would not help: _handle_askpass_query does an exact-match
dict lookup on the nonce before it ever touches the secret, so anyone who
doesn't have the exact nonce already gets `nonce_unknown` with no payload at
all, and anyone who does have it could derive the same key. Running the
daemon as a separate OS user from the agent remains the one mitigation that
is actually kernel-enforced (0600 socket ownership would then genuinely
exclude the agent's UID) -- see totp.py's docstring for the same caveat
about the (unused, in relay mode) TOTP secret.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import protocol, sudo_cache, totp
from . import paths as paths_mod
from .errors import ProtocolError
from .nonce import ReplayGuard

DEFAULT_TTL_SECONDS = 120
DEFAULT_APPROVAL_WINDOW_SECONDS = 15
CONNECTION_READ_TIMEOUT = 5
MAX_RELAY_PASSWORD_ATTEMPTS = 5


@dataclass
class PendingRequest:
    request: protocol.RequestMsg
    future: asyncio.Future = field(repr=False)
    display_id: int


async def _default_input_reader(prompt: str) -> str:
    return await asyncio.to_thread(input, prompt)


async def _default_password_reader(prompt: str) -> str:
    # getpass reads from /dev/tty directly and disables echo -- unlike a TOTP
    # code, a real sudo password should never be visible on screen.
    return await asyncio.to_thread(getpass.getpass, prompt)


def _default_record_success(credential_mode: str, now: float) -> None:
    # Best-effort, human-side-only receipt that a real credential was actually
    # validated against the real `sudo` on this machine -- not a synthetic
    # check. `doctor` reads this (non-interactively, from the agent's side)
    # so an agent can tell "the pipeline has proven it works" apart from
    # "the socket exists and permissions look fine", without ever blocking
    # on a human. Written atomically (temp file + rename) so a concurrent
    # `doctor` read never sees a half-written file.
    path = paths_mod.last_success_path()
    payload = json.dumps({"ts": now, "credential_mode": credential_mode}) + "\n"
    tmp_path = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(str(tmp_path), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        os.replace(tmp_path, path)
    except OSError as exc:
        # Diagnostic history, not the approval itself -- never fail an
        # already-approved request over this.
        print(f"[agent-sudo] could not record successful approval to {path}: {exc}", file=sys.stderr)


class Daemon:
    def __init__(
        self,
        secret: str | None = None,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        approval_window_seconds: float = DEFAULT_APPROVAL_WINDOW_SECONDS,
        credential_mode: str = "relay",
        now=time.time,
        input_reader=_default_input_reader,
        password_reader=_default_password_reader,
        refresh_timestamp=sudo_cache.refresh_timestamp,
        validate_password=sudo_cache.validate_password,
        record_success=_default_record_success,
    ):
        if credential_mode not in ("timestamp", "relay"):
            raise ValueError(f"unknown credential_mode: {credential_mode!r}")
        if credential_mode == "timestamp" and not secret:
            raise ValueError("credential_mode='timestamp' requires a TOTP secret")

        self.ttl_seconds = ttl_seconds
        self.approval_window_seconds = approval_window_seconds
        self.credential_mode = credential_mode
        self._now = now
        self._input_reader = input_reader
        self._password_reader = password_reader
        self._refresh_timestamp = refresh_timestamp
        self._validate_password = validate_password
        self._record_success = record_success

        self.totp = totp.TotpVerifier(secret, now=now) if credential_mode == "timestamp" else None
        self.replay_guard = ReplayGuard()
        self.pending: dict[str, PendingRequest] = {}
        self.queue: asyncio.Queue[PendingRequest] = asyncio.Queue()
        self._worker_task: asyncio.Task | None = None
        self._request_counter = 0  # monotonic, human-facing #N -- distinguishes requests at a glance
        # display_id of whichever request the worker is actively deciding right
        # now, or None between requests. Lets _handle_request announce a new
        # arrival in real time instead of stamping a stale "(N queued)" count
        # into a block that's only ever printed once (see _print_request).
        self._active_display_id: int | None = None

        # relay mode only: nonce -> approved-but-not-yet-consumed password.
        # Populated by the approval worker, consumed (popped) by the first
        # askpass_query for that nonce, and evicted after approval_window_seconds
        # regardless, so an approval that's never consumed doesn't linger forever.
        self._approved_secrets: dict[str, str] = {}

    # -- connection handling -------------------------------------------------

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=CONNECTION_READ_TIMEOUT)
            except asyncio.TimeoutError:
                return
            if not line:
                return

            try:
                msg = protocol.decode_message(line)
            except ProtocolError as exc:
                print(f"[agent-sudo] rejected malformed message: {exc}", file=sys.stderr)
                return

            if isinstance(msg, protocol.RequestMsg):
                await self._handle_request(msg, writer)
            elif isinstance(msg, protocol.AskpassQueryMsg):
                await self._handle_askpass_query(msg, writer)
            else:
                # verdict/askpass_reply are daemon->client only; a client sending one is malformed
                print(f"[agent-sudo] rejected out-of-place message type: {msg.type}", file=sys.stderr)
        finally:
            writer.close()

    async def _reply(self, writer: asyncio.StreamWriter, msg: protocol.Message) -> None:
        writer.write(protocol.encode_message(msg))
        await writer.drain()

    async def _handle_request(self, msg: protocol.RequestMsg, writer: asyncio.StreamWriter) -> None:
        if msg.nonce in self.pending or self.replay_guard.was_resolved(msg.nonce):
            verdict = protocol.VerdictMsg(nonce=msg.nonce, result="deny", reason="nonce_reuse")
            await self._reply(writer, verdict)
            return

        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._request_counter += 1
        req = PendingRequest(request=msg, future=future, display_id=self._request_counter)
        self.pending[msg.nonce] = req
        await self.queue.put(req)
        if self._active_display_id is not None:
            # Leading newline: getpass leaves an unanswered "sudo password:"
            # prompt on screen with no trailing newline, so this would
            # otherwise run into the end of that prompt text.
            print(
                f"\n[agent-sudo] request #{req.display_id} (nonce {msg.nonce[:8]}...) "
                f"queued behind #{self._active_display_id}",
                file=sys.stdout,
            )

        result, reason = await future

        self.replay_guard.mark_resolved(msg.nonce)
        self.pending.pop(msg.nonce, None)

        if result == "approve":
            verdict = protocol.VerdictMsg(
                nonce=msg.nonce, result="approve", expires_at=self._now() + self.approval_window_seconds
            )
        else:
            verdict = protocol.VerdictMsg(nonce=msg.nonce, result="deny", reason=reason)
        await self._reply(writer, verdict)

    async def _handle_askpass_query(
        self, msg: protocol.AskpassQueryMsg, writer: asyncio.StreamWriter
    ) -> None:
        if self.credential_mode == "relay":
            secret = self._approved_secrets.pop(msg.nonce, None)
            if secret is None:
                print(
                    f"[agent-sudo] askpass query for unknown/expired/already-used nonce "
                    f"{msg.nonce[:8]}... (pid {msg.pid})",
                    file=sys.stderr,
                )
                reply = protocol.AskpassReplyMsg(nonce=msg.nonce, result="deny", reason="nonce_unknown")
            else:
                reply = protocol.AskpassReplyMsg(nonce=msg.nonce, result="approve", secret=secret)
                # Strongest available proof for this mode: the real askpass
                # binary really was invoked by a real `sudo -A`, really
                # queried this socket, and really got a real secret back.
                self._record_success(self.credential_mode, self._now())
            await self._reply(writer, reply)
            return

        # "timestamp" mode: the askpass helper should never legitimately need to
        # be invoked, because the wrapper doesn't call `sudo -A` until the daemon
        # has already refreshed the timestamp cache. Its invocation at all is
        # itself the misconfiguration signal.
        print(
            f"[agent-sudo] WARNING: askpass invoked unexpectedly for nonce "
            f"{msg.nonce[:8]}... (pid {msg.pid}). The two-phase approval did not "
            f"suppress sudo's own password prompt — check `agent-sudo doctor` "
            f"(likely missing `Defaults !tty_tickets` in sudoers, or a stale timestamp).",
            file=sys.stderr,
        )
        reply = protocol.AskpassReplyMsg(
            nonce=msg.nonce, result="deny", reason="askpass_invoked_unexpectedly"
        )
        await self._reply(writer, reply)

    def _schedule_secret_expiry(self, nonce: str) -> None:
        async def _expire() -> None:
            await asyncio.sleep(self.approval_window_seconds)
            self._approved_secrets.pop(nonce, None)

        asyncio.ensure_future(_expire())

    # -- approval worker -------------------------------------------------------

    async def _approval_worker(self) -> None:
        while True:
            req = await self.queue.get()
            if req.request.nonce not in self.pending:
                continue  # resolved/expired before the worker got to it
            self._active_display_id = req.display_id
            try:
                if self.credential_mode == "relay":
                    result, reason = await self._process_one_relay(req)
                else:
                    result, reason = await self._process_one_timestamp(req)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                # Must never take down the worker loop -- one bad request fails
                # closed, not the whole daemon.
                print(
                    f"[agent-sudo] internal error processing {req.request.nonce[:8]}...: {exc}",
                    file=sys.stderr,
                )
                result, reason = "deny", "internal_error"
            finally:
                self._active_display_id = None
            self._print_outcome(req, result, reason)
            if not req.future.done():
                req.future.set_result((result, reason))

    async def _process_one_relay(self, req: PendingRequest) -> tuple[str, str | None]:
        deadline = req.request.issued_at + self.ttl_seconds
        self._print_request(req)
        attempts = 0
        while True:
            remaining = deadline - self._now()
            if remaining <= 0:
                return "deny", "timeout"

            input_task = asyncio.ensure_future(self._password_reader("sudo password (blank to deny): "))
            done, _pending = await asyncio.wait({input_task}, timeout=remaining)

            if input_task not in done:
                input_task.add_done_callback(_discard_stray_input)
                return "deny", "timeout"

            try:
                password = input_task.result()
            except Exception:  # pylint: disable=broad-exception-caught  # fail closed on any read error
                return "deny", "timeout"

            if not password:
                return "deny", "human_denied"

            ok = await asyncio.to_thread(self._validate_password, password)
            if ok:
                self._approved_secrets[req.request.nonce] = password
                self._schedule_secret_expiry(req.request.nonce)
                return "approve", None

            attempts += 1
            if attempts >= MAX_RELAY_PASSWORD_ATTEMPTS:
                return "deny", "password_rate_limited"
            self._print_retry(req, "invalid sudo password", deadline)

    async def _process_one_timestamp(self, req: PendingRequest) -> tuple[str, str | None]:
        deadline = req.request.issued_at + self.ttl_seconds
        self._print_request(req)
        while True:
            remaining = deadline - self._now()
            if remaining <= 0:
                return "deny", "timeout"

            input_task = asyncio.ensure_future(self._input_reader("Enter 6-digit TOTP (or 'deny'): "))
            done, _pending = await asyncio.wait({input_task}, timeout=remaining)

            if input_task not in done:
                input_task.add_done_callback(_discard_stray_input)
                return "deny", "timeout"

            try:
                raw = input_task.result()
            except Exception:  # pylint: disable=broad-exception-caught  # fail closed on any read error
                return "deny", "timeout"

            answer = (raw or "").strip().lower()
            if answer in ("", "d", "deny", "n", "no"):
                return "deny", "human_denied"

            if self.totp.locked():
                return "deny", "totp_rate_limited"

            accepted, fail_reason = self.totp.verify(answer)
            if accepted:
                ok = await asyncio.to_thread(self._refresh_timestamp)
                if not ok:
                    return "deny", "sudo_refresh_failed"
                # Strongest available proof for this mode: a real `sudo -v`
                # actually succeeded in the daemon's own session. Askpass is
                # never expected to be consulted here, so this is the
                # equivalent of the relay-mode askpass_query receipt above.
                self._record_success(self.credential_mode, self._now())
                return "approve", None

            self._print_retry(req, f"invalid code ({fail_reason})", deadline)

    def _print_request(self, req: PendingRequest) -> None:
        sep = "-" * 60
        print(
            f"\n{sep}\n"
            f"[agent-sudo] request #{req.display_id} (nonce {req.request.nonce[:8]}...)\n"
            f"  cwd:     {req.request.cwd}\n"
            f"  command: {' '.join(req.request.command)}\n"
            f"  from pid {req.request.pid}, uid {req.request.uid} -- expires in {self.ttl_seconds:.0f}s"
            f"\n{sep}",
            file=sys.stdout,
        )

    def _print_retry(self, req: PendingRequest, problem: str, deadline: float) -> None:
        remaining = deadline - self._now()
        print(
            f"[agent-sudo] request #{req.display_id}: {problem}, {remaining:.0f}s left -- try again",
            file=sys.stderr,
        )

    def _print_outcome(self, req: PendingRequest, result: str, reason: str | None) -> None:
        if result == "approve":
            print(
                f"[agent-sudo] request #{req.display_id} (nonce {req.request.nonce[:8]}...) "
                f"-- APPROVED, relaying credential",
                file=sys.stdout,
            )
        else:
            print(
                f"[agent-sudo] request #{req.display_id} (nonce {req.request.nonce[:8]}...) "
                f"-- DENIED ({reason})",
                file=sys.stdout,
            )

    # -- socket lifecycle -------------------------------------------------------

    def _ensure_fresh_socket(self, sock_path: Path) -> None:
        if not sock_path.exists():
            return
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(1)
        try:
            probe.connect(str(sock_path))
        except OSError:
            sock_path.unlink(missing_ok=True)
            return
        finally:
            probe.close()
        raise RuntimeError(f"agent-sudo daemon already running (socket {sock_path} is live)")

    async def serve(self, sock_path: Path) -> None:
        self._ensure_fresh_socket(sock_path)
        old_umask = os.umask(0o177)
        try:
            server = await asyncio.start_unix_server(self.handle_connection, path=str(sock_path))
        finally:
            os.umask(old_umask)
        os.chmod(sock_path, 0o600)

        self._worker_task = asyncio.create_task(self._approval_worker())
        print(
            f"[agent-sudo] daemon listening on {sock_path} (credential_mode={self.credential_mode})",
            file=sys.stderr,
        )
        try:
            async with server:
                await server.serve_forever()
        finally:
            self._worker_task.cancel()


def _discard_stray_input(task: asyncio.Task) -> None:
    if task.cancelled():
        return
    if task.exception() is None:
        print("[agent-sudo] discarded input for an already-expired request", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(prog="agent-sudo-daemon")
    parser.add_argument("--ttl", type=float, default=DEFAULT_TTL_SECONDS, help="seconds to wait for approval")
    parser.add_argument("--credential-mode", choices=["relay", "timestamp"], default="relay")
    args = parser.parse_args()

    paths_mod.ensure_base_dir()

    secret = None
    if args.credential_mode == "timestamp":
        secret_path = paths_mod.totp_secret_path()
        if not secret_path.exists():
            print(
                f"[agent-sudo] no TOTP secret at {secret_path} -- run `scripts/enroll_totp.py` first "
                "(only needed for --credential-mode=timestamp)",
                file=sys.stderr,
            )
            raise SystemExit(1)
        secret = totp.load_secret(secret_path)

    daemon = Daemon(secret, ttl_seconds=args.ttl, credential_mode=args.credential_mode)

    try:
        asyncio.run(daemon.serve(paths_mod.socket_path()))
    except KeyboardInterrupt:
        pass
    except RuntimeError as exc:
        print(f"[agent-sudo] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
