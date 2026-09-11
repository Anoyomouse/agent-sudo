"""End-to-end tests against a real Daemon + real Unix socket, with the human
side replaced by a scripted input_reader instead of a live TOTP entry. This
is the harness described in the design plan: it proves the approve/deny/
timeout/nonce-reuse/askpass-safety-net behaviors without a human in the loop.
"""

from __future__ import annotations

import asyncio
import time

import pyotp
import pytest

from agent_sudo import protocol
from agent_sudo.daemon import Daemon

SECRET = "JBSWY3DPEHPK3PXP"


def scripted_input(answers: list[str]):
    """Returns an input_reader that feeds pre-scripted answers in order. Once
    exhausted, further calls hang until the caller times out/cancels -- this
    stands in for "nobody answers before the TTL expires"."""
    answers = list(answers)

    async def _reader(prompt: str) -> str:  # pylint: disable=unused-argument
        if answers:
            return answers.pop(0)
        await asyncio.Event().wait()
        raise AssertionError("unreachable")  # pragma: no cover

    return _reader


async def _wait_for_socket(path, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"socket {path} never appeared")


async def _send_and_recv(sock_path, msg: protocol.Message) -> protocol.Message:
    reader, writer = await asyncio.open_unix_connection(str(sock_path))
    try:
        writer.write(protocol.encode_message(msg))
        await writer.drain()
        line = await reader.readline()
    finally:
        writer.close()
        await writer.wait_closed()
    return protocol.decode_message(line)


async def _start_daemon(tmp_path, **daemon_kwargs):
    sock_path = tmp_path / "agent-sudo.sock"
    daemon_kwargs.setdefault("refresh_timestamp", lambda: True)
    daemon = Daemon(SECRET, **daemon_kwargs)
    task = asyncio.create_task(daemon.serve(sock_path))
    await _wait_for_socket(sock_path)
    return daemon, sock_path, task


async def _stop(task: asyncio.Task) -> None:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def test_approve_flow_refreshes_timestamp_and_never_sends_a_password(tmp_path):
    code = pyotp.TOTP(SECRET).at(time.time())
    refresh_calls = []
    _, sock_path, task = await _start_daemon(
        tmp_path,
        credential_mode="timestamp",
        ttl_seconds=5,
        input_reader=scripted_input([code]),
        refresh_timestamp=lambda: (refresh_calls.append(1) or True),
    )
    try:
        req = protocol.RequestMsg(nonce="n-approve", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)

        assert verdict.result == "approve"
        assert verdict.expires_at is not None
        assert refresh_calls == [1]
    finally:
        await _stop(task)


async def test_human_denies_explicitly(tmp_path):
    _, sock_path, task = await _start_daemon(
        tmp_path, credential_mode="timestamp", ttl_seconds=5, input_reader=scripted_input(["deny"])
    )
    try:
        req = protocol.RequestMsg(nonce="n-deny", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)
        assert verdict.result == "deny"
        assert verdict.reason == "human_denied"
    finally:
        await _stop(task)


async def test_sudo_refresh_failure_denies(tmp_path):
    code = pyotp.TOTP(SECRET).at(time.time())
    _, sock_path, task = await _start_daemon(
        tmp_path,
        credential_mode="timestamp",
        ttl_seconds=5,
        input_reader=scripted_input([code]),
        refresh_timestamp=lambda: False,
    )
    try:
        req = protocol.RequestMsg(nonce="n-refresh-fail", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)
        assert verdict.result == "deny"
        assert verdict.reason == "sudo_refresh_failed"
    finally:
        await _stop(task)


async def test_timeout_denies_when_nobody_answers(tmp_path):
    _, sock_path, task = await _start_daemon(
        tmp_path, credential_mode="timestamp", ttl_seconds=0.2, input_reader=scripted_input([])
    )
    try:
        req = protocol.RequestMsg(nonce="n-timeout", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=3)
        assert verdict.result == "deny"
        assert verdict.reason == "timeout"
    finally:
        await _stop(task)


async def test_askpass_always_denies_in_timestamp_mode(tmp_path):
    code = pyotp.TOTP(SECRET).at(time.time())
    _, sock_path, task = await _start_daemon(
        tmp_path, credential_mode="timestamp", ttl_seconds=5, input_reader=scripted_input([code])
    )
    try:
        req = protocol.RequestMsg(nonce="n-askpass", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)
        assert verdict.result == "approve"

        query = protocol.AskpassQueryMsg(nonce="n-askpass", pid=1)
        reply = await asyncio.wait_for(_send_and_recv(sock_path, query), timeout=5)
        assert isinstance(reply, protocol.AskpassReplyMsg)
        assert reply.result == "deny"
        assert reply.reason == "askpass_invoked_unexpectedly"
        assert reply.secret is None
    finally:
        await _stop(task)


async def test_nonce_reuse_denied_without_consuming_a_second_prompt(tmp_path):
    # Only one scripted answer: if reuse detection wrongly re-prompted for the
    # second request, that request would hang on the exhausted input queue
    # and the outer wait_for below would time out, failing the test.
    code = pyotp.TOTP(SECRET).at(time.time())
    _, sock_path, task = await _start_daemon(
        tmp_path, credential_mode="timestamp", ttl_seconds=5, input_reader=scripted_input([code])
    )
    try:
        req = protocol.RequestMsg(nonce="n-dup", pid=1, uid=1, cwd="/", command=["true"])
        verdict1 = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)
        assert verdict1.result == "approve"

        verdict2 = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=2)
        assert verdict2.result == "deny"
        assert verdict2.reason == "nonce_reuse"
    finally:
        await _stop(task)


async def test_second_daemon_refuses_to_start_on_live_socket(tmp_path):
    _, sock_path, task = await _start_daemon(tmp_path, ttl_seconds=5, input_reader=scripted_input([]))
    try:
        other = Daemon(SECRET, refresh_timestamp=lambda: True)
        with pytest.raises(RuntimeError):
            await other.serve(sock_path)
    finally:
        await _stop(task)


async def test_timestamp_mode_requires_secret():
    with pytest.raises(ValueError):
        Daemon(credential_mode="timestamp")


# -- relay mode ---------------------------------------------------------------


async def _start_relay_daemon(tmp_path, **kwargs):
    kwargs.setdefault("validate_password", lambda pw: pw == "correct-horse")
    return await _start_daemon(tmp_path, credential_mode="relay", **kwargs)


async def test_relay_approve_relays_password_exactly_once(tmp_path):
    _, sock_path, task = await _start_relay_daemon(
        tmp_path, ttl_seconds=5, password_reader=scripted_input(["correct-horse"])
    )
    try:
        req = protocol.RequestMsg(nonce="n-relay", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)
        assert verdict.result == "approve"

        query = protocol.AskpassQueryMsg(nonce="n-relay", pid=1)
        reply = await asyncio.wait_for(_send_and_recv(sock_path, query), timeout=5)
        assert isinstance(reply, protocol.AskpassReplyMsg)
        assert reply.result == "approve"
        assert reply.secret == "correct-horse"

        # single-use: a second query for the same nonce gets nothing
        reply2 = await asyncio.wait_for(_send_and_recv(sock_path, query), timeout=5)
        assert reply2.result == "deny"
        assert reply2.reason == "nonce_unknown"
    finally:
        await _stop(task)


async def test_relay_wrong_password_reprompts_then_times_out(tmp_path):
    _, sock_path, task = await _start_relay_daemon(
        tmp_path, ttl_seconds=0.3, password_reader=scripted_input(["nope"])
    )
    try:
        req = protocol.RequestMsg(nonce="n-relay-wrong", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=3)
        assert verdict.result == "deny"
        assert verdict.reason == "timeout"
    finally:
        await _stop(task)


async def test_relay_empty_password_denies_immediately(tmp_path):
    _, sock_path, task = await _start_relay_daemon(
        tmp_path, ttl_seconds=5, password_reader=scripted_input([""])
    )
    try:
        req = protocol.RequestMsg(nonce="n-relay-empty", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)
        assert verdict.result == "deny"
        assert verdict.reason == "human_denied"
    finally:
        await _stop(task)


async def test_relay_rate_limits_after_max_wrong_attempts(tmp_path):
    _, sock_path, task = await _start_relay_daemon(
        tmp_path, ttl_seconds=30, password_reader=scripted_input(["nope"] * 5)
    )
    try:
        req = protocol.RequestMsg(nonce="n-relay-limit", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)
        assert verdict.result == "deny"
        assert verdict.reason == "password_rate_limited"
    finally:
        await _stop(task)


async def test_relay_secret_expires_if_never_consumed(tmp_path):
    _, sock_path, task = await _start_relay_daemon(
        tmp_path,
        ttl_seconds=5,
        approval_window_seconds=0.1,
        password_reader=scripted_input(["correct-horse"]),
    )
    try:
        req = protocol.RequestMsg(nonce="n-relay-expire", pid=1, uid=1, cwd="/", command=["true"])
        verdict = await asyncio.wait_for(_send_and_recv(sock_path, req), timeout=5)
        assert verdict.result == "approve"

        await asyncio.sleep(0.3)  # let the expiry task pop it

        query = protocol.AskpassQueryMsg(nonce="n-relay-expire", pid=1)
        reply = await asyncio.wait_for(_send_and_recv(sock_path, query), timeout=5)
        assert reply.result == "deny"
        assert reply.reason == "nonce_unknown"
    finally:
        await _stop(task)
