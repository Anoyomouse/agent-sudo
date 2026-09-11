# SPDX-License-Identifier: MIT
"""Shared pytest fixtures."""

import pytest

from agent_sudo import paths as paths_mod

# Arbitrary but fixed base32 secret, used across tests so codes are
# deterministic and don't require a real enrolled secret on disk.
FIXED_TOTP_SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def tmp_home(tmp_path, monkeypatch):
    """Redirect ~/.agent-sudo/ to a temp dir for tests that touch paths.py."""
    home_dir = tmp_path / "agent-sudo-home"
    monkeypatch.setenv("AGENT_SUDO_HOME", str(home_dir))
    paths_mod.ensure_base_dir()
    return home_dir
