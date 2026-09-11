"""Wire protocol: newline-delimited JSON, one message per line.

Transport-agnostic on purpose — encode_message()/decode_message() work on
bytes so both the blocking-socket clients (cli.py, askpass.py) and the
asyncio daemon can share the same framing and validation logic.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field

from .errors import ProtocolError

PROTOCOL_VERSION = 1
MAX_LINE_BYTES = 64 * 1024

VALID_DENY_REASONS = {
    "totp_invalid",
    "totp_rate_limited",
    "password_invalid",
    "password_rate_limited",
    "timeout",
    "nonce_reuse",
    "nonce_unknown",
    "human_denied",
    "sudo_refresh_failed",
    "askpass_invoked_unexpectedly",
    "malformed_request",
    "stale_verdict",
}


@dataclass
class RequestMsg:
    nonce: str
    pid: int
    uid: int
    cwd: str
    command: list[str]
    issued_at: float = field(default_factory=time.time)
    type: str = "request"
    v: int = PROTOCOL_VERSION


@dataclass
class VerdictMsg:
    nonce: str
    result: str  # "approve" | "deny"
    expires_at: float | None = None
    reason: str | None = None
    type: str = "verdict"
    v: int = PROTOCOL_VERSION

    def __post_init__(self):
        if self.result not in ("approve", "deny"):
            raise ValueError(f"invalid verdict result: {self.result!r}")
        if self.result == "deny" and self.reason is None:
            raise ValueError("deny verdict requires a reason")
        if self.result == "approve" and self.expires_at is None:
            raise ValueError("approve verdict requires expires_at")


@dataclass
class AskpassQueryMsg:
    nonce: str
    pid: int
    type: str = "askpass_query"
    v: int = PROTOCOL_VERSION


@dataclass
class AskpassReplyMsg:
    nonce: str
    result: str  # "approve" | "deny"
    reason: str | None = None
    secret: str | None = None  # only ever populated in Option A (password-cache) mode
    type: str = "askpass_reply"
    v: int = PROTOCOL_VERSION


_TYPE_MAP = {
    "request": RequestMsg,
    "verdict": VerdictMsg,
    "askpass_query": AskpassQueryMsg,
    "askpass_reply": AskpassReplyMsg,
}

Message = RequestMsg | VerdictMsg | AskpassQueryMsg | AskpassReplyMsg


def encode_message(msg: Message) -> bytes:
    line = json.dumps(asdict(msg), separators=(",", ":")) + "\n"
    encoded = line.encode("utf-8")
    if len(encoded) > MAX_LINE_BYTES:
        raise ProtocolError(f"encoded message exceeds {MAX_LINE_BYTES} bytes")
    return encoded


def read_frame(sock, max_bytes: int = MAX_LINE_BYTES) -> bytes:
    """Read one newline-delimited frame from a blocking socket.

    Shared by cli.py and askpass.py, both of which use plain blocking
    sockets (unlike the daemon, which is asyncio-based).
    """
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\n" in buf:
            break
        if len(buf) > max_bytes:
            raise ProtocolError(f"response exceeds {max_bytes} bytes")
    idx = buf.find(b"\n")
    return bytes(buf) if idx == -1 else bytes(buf[: idx + 1])


def decode_message(raw: bytes) -> Message:
    if len(raw) > MAX_LINE_BYTES:
        raise ProtocolError(f"message exceeds {MAX_LINE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"invalid utf-8: {exc}") from exc

    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"invalid json: {exc}") from exc

    if not isinstance(obj, dict):
        raise ProtocolError("message must be a JSON object")

    version = obj.get("v")
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {version!r}")

    msg_type = obj.get("type")
    cls = _TYPE_MAP.get(msg_type)
    if cls is None:
        raise ProtocolError(f"unknown message type: {msg_type!r}")

    obj.pop("v", None)
    obj.pop("type", None)
    try:
        return cls(**obj)
    except TypeError as exc:
        raise ProtocolError(f"malformed {msg_type} message: {exc}") from exc
    except ValueError as exc:
        raise ProtocolError(f"invalid {msg_type} message: {exc}") from exc
