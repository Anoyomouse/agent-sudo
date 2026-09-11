"""Wire-format encode/decode round-trips and malformed-input handling."""

import pytest

from agent_sudo import protocol
from agent_sudo.errors import ProtocolError


def test_request_roundtrip():
    msg = protocol.RequestMsg(nonce="abc", pid=1, uid=2, cwd="/tmp", command=["ls", "-la"])
    decoded = protocol.decode_message(protocol.encode_message(msg))
    assert decoded == msg


def test_verdict_approve_roundtrip():
    msg = protocol.VerdictMsg(nonce="abc", result="approve", expires_at=123.0)
    decoded = protocol.decode_message(protocol.encode_message(msg))
    assert decoded == msg


def test_verdict_deny_roundtrip():
    msg = protocol.VerdictMsg(nonce="abc", result="deny", reason="timeout")
    decoded = protocol.decode_message(protocol.encode_message(msg))
    assert decoded == msg


def test_verdict_deny_requires_reason():
    with pytest.raises(ValueError):
        protocol.VerdictMsg(nonce="abc", result="deny")


def test_verdict_approve_requires_expiry():
    with pytest.raises(ValueError):
        protocol.VerdictMsg(nonce="abc", result="approve")


def test_verdict_rejects_bad_result():
    with pytest.raises(ValueError):
        protocol.VerdictMsg(nonce="abc", result="maybe")


def test_askpass_query_roundtrip():
    msg = protocol.AskpassQueryMsg(nonce="abc", pid=99)
    decoded = protocol.decode_message(protocol.encode_message(msg))
    assert decoded == msg


def test_askpass_reply_roundtrip():
    msg = protocol.AskpassReplyMsg(nonce="abc", result="deny", reason="askpass_invoked_unexpectedly")
    decoded = protocol.decode_message(protocol.encode_message(msg))
    assert decoded == msg


def test_encoded_line_is_single_newline_terminated():
    msg = protocol.AskpassQueryMsg(nonce="abc", pid=1)
    encoded = protocol.encode_message(msg)
    assert encoded.count(b"\n") == 1
    assert encoded.endswith(b"\n")


def test_decode_malformed_json():
    with pytest.raises(ProtocolError):
        protocol.decode_message(b"not json\n")


def test_decode_not_object():
    with pytest.raises(ProtocolError):
        protocol.decode_message(b"[1,2,3]\n")


def test_decode_wrong_version():
    with pytest.raises(ProtocolError):
        protocol.decode_message(b'{"v":2,"type":"request"}\n')


def test_decode_missing_version():
    with pytest.raises(ProtocolError):
        protocol.decode_message(b'{"type":"request"}\n')


def test_decode_unknown_type():
    with pytest.raises(ProtocolError):
        protocol.decode_message(b'{"v":1,"type":"bogus"}\n')


def test_decode_missing_fields():
    with pytest.raises(ProtocolError):
        protocol.decode_message(b'{"v":1,"type":"request"}\n')


def test_decode_invalid_utf8():
    with pytest.raises(ProtocolError):
        protocol.decode_message(b"\xff\xfe\n")


def test_encode_oversized_rejected():
    huge_command = ["x" * (protocol.MAX_LINE_BYTES + 1)]
    msg = protocol.RequestMsg(nonce="abc", pid=1, uid=1, cwd="/", command=huge_command)
    with pytest.raises(ProtocolError):
        protocol.encode_message(msg)


def test_decode_oversized_rejected():
    raw = b"x" * (protocol.MAX_LINE_BYTES + 1)
    with pytest.raises(ProtocolError):
        protocol.decode_message(raw)
