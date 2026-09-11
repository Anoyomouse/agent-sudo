"""Resolution and permission handling for everything under ~/.agent-sudo/.

All paths are derived from a single base directory so tests can redirect the
whole tree by setting AGENT_SUDO_HOME, without monkeypatching each path
individually.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


def base_dir() -> Path:
    override = os.environ.get("AGENT_SUDO_HOME")
    if override:
        return Path(override)
    return Path.home() / ".agent-sudo"


def socket_path() -> Path:
    return base_dir() / "agent-sudo.sock"


def totp_secret_path() -> Path:
    return base_dir() / "totp_secret"


def password_cache_path() -> Path:
    return base_dir() / "sudo_pw.age"


def ensure_base_dir() -> Path:
    """Create the base directory 0700 if missing; verify perms/ownership if present."""
    path = base_dir()
    if not path.exists():
        # Set umask around mkdir too: mkdir's mode is still subject to umask.
        old_umask = os.umask(0o077)
        try:
            path.mkdir(parents=True, exist_ok=True)
        finally:
            os.umask(old_umask)
        os.chmod(path, DIR_MODE)
        return path

    st = path.stat()
    if st.st_uid != os.getuid():
        raise PermissionError(f"{path} is not owned by the current user")
    if stat.S_IMODE(st.st_mode) != DIR_MODE:
        os.chmod(path, DIR_MODE)
    return path


def check_perms(path: Path, expected_mode: int) -> list[str]:
    """Return a list of human-readable problems with path's ownership/permissions."""
    problems = []
    try:
        st = path.stat()
    except FileNotFoundError:
        return [f"{path} does not exist"]
    if st.st_uid != os.getuid():
        problems.append(f"{path} is not owned by the current user (uid {st.st_uid})")
    mode = stat.S_IMODE(st.st_mode)
    if mode != expected_mode:
        problems.append(f"{path} has mode {oct(mode)}, expected {oct(expected_mode)}")
    return problems
