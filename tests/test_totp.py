# SPDX-License-Identifier: MIT
"""TotpVerifier accept/reject/replay/rate-limit behavior, with an injectable clock."""

import pyotp

from agent_sudo.totp import DEFAULT_INTERVAL, TotpVerifier

SECRET = "JBSWY3DPEHPK3PXP"


class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _wrong_code(valid_code: str) -> str:
    return "".join(str((int(d) + 1) % 10) for d in valid_code)


def test_accepts_valid_code():
    clock = FakeClock()
    verifier = TotpVerifier(SECRET, now=clock)
    code = pyotp.TOTP(SECRET).at(clock.t)
    accepted, reason = verifier.verify(code)
    assert accepted
    assert reason is None


def test_rejects_wrong_code():
    clock = FakeClock()
    verifier = TotpVerifier(SECRET, now=clock)
    valid = pyotp.TOTP(SECRET).at(clock.t)
    accepted, reason = verifier.verify(_wrong_code(valid))
    assert not accepted
    assert reason == "invalid"


def test_rejects_non_digit_code():
    verifier = TotpVerifier(SECRET, now=FakeClock())
    accepted, reason = verifier.verify("abcdef")
    assert not accepted
    assert reason == "invalid"


def test_rejects_replay_of_same_code():
    clock = FakeClock()
    verifier = TotpVerifier(SECRET, now=clock)
    code = pyotp.TOTP(SECRET).at(clock.t)
    assert verifier.verify(code)[0]
    accepted_again, reason = verifier.verify(code)
    assert not accepted_again
    assert reason == "invalid"


def test_accepts_new_code_after_step_advances():
    clock = FakeClock()
    verifier = TotpVerifier(SECRET, now=clock)
    code1 = pyotp.TOTP(SECRET).at(clock.t)
    assert verifier.verify(code1)[0]

    clock.advance(DEFAULT_INTERVAL * 3)
    code2 = pyotp.TOTP(SECRET).at(clock.t)
    accepted, reason = verifier.verify(code2)
    assert accepted
    assert reason is None


def test_rate_limits_after_max_failed_attempts():
    clock = FakeClock()
    verifier = TotpVerifier(SECRET, now=clock, max_failed_attempts=3, lockout_seconds=60)
    valid = pyotp.TOTP(SECRET).at(clock.t)
    wrong = _wrong_code(valid)

    for _ in range(3):
        accepted, reason = verifier.verify(wrong)
        assert not accepted
        assert reason == "invalid"

    assert verifier.locked()
    accepted, reason = verifier.verify(valid)
    assert not accepted
    assert reason == "rate_limited"

    clock.advance(61)
    assert not verifier.locked()
