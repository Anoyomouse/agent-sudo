# SPDX-License-Identifier: MIT
"""Nonce generation format and ReplayGuard behavior."""

from agent_sudo import nonce

_URLSAFE_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def test_generate_is_urlsafe_and_high_entropy():
    n = nonce.generate()
    assert isinstance(n, str)
    assert len(n) >= 32
    assert set(n) <= _URLSAFE_ALPHABET


def test_generate_is_unique():
    values = {nonce.generate() for _ in range(1000)}
    assert len(values) == 1000


def test_replay_guard_marks_and_checks():
    guard = nonce.ReplayGuard()
    assert not guard.was_resolved("a")
    guard.mark_resolved("a")
    assert guard.was_resolved("a")
    assert not guard.was_resolved("b")


def test_replay_guard_is_bounded_lru():
    guard = nonce.ReplayGuard(max_size=3)
    for i in range(5):
        guard.mark_resolved(str(i))
    assert not guard.was_resolved("0")
    assert not guard.was_resolved("1")
    assert guard.was_resolved("2")
    assert guard.was_resolved("3")
    assert guard.was_resolved("4")
