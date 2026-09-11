# SPDX-License-Identifier: MIT
"""check_last_live_approval behavior -- must never block/prompt, only ever
read whatever the daemon already wrote."""

from __future__ import annotations

import json
import time

from agent_sudo import doctor, paths


def test_missing_receipt_fails_without_blocking(tmp_home):  # pylint: disable=unused-argument
    ok, message = doctor.check_last_live_approval()
    assert ok is False
    assert "does not exist" in message


def test_valid_receipt_passes_and_reports_mode(tmp_home):  # pylint: disable=unused-argument
    path = paths.last_success_path()
    path.write_text(json.dumps({"ts": time.time(), "credential_mode": "relay"}))

    ok, message = doctor.check_last_live_approval()
    assert ok is True
    assert "credential_mode=relay" in message


def test_malformed_receipt_fails(tmp_home):  # pylint: disable=unused-argument
    path = paths.last_success_path()
    path.write_text("not json")

    ok, message = doctor.check_last_live_approval()
    assert ok is False
    assert "could not read/parse" in message
