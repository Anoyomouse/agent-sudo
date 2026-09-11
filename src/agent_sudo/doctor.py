"""`agent-sudo doctor` -- environment/sudoers preflight checks.

In "timestamp" mode, catches the missing-`!tty_tickets` prerequisite
proactively, instead of letting the human discover it later as a wall of
confusing "askpass invoked unexpectedly" denials from the daemon. That check
(and the TOTP secret check) is skipped entirely in "relay" mode, which needs
neither.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys

from . import paths

CheckResult = tuple[bool, str]


def check_daemon_reachable() -> CheckResult:
    sock_path = paths.socket_path()
    if not sock_path.exists():
        return False, f"{sock_path} does not exist -- is the daemon running?"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(str(sock_path))
    except OSError as exc:
        return False, f"cannot connect to {sock_path}: {exc}"
    finally:
        sock.close()
    return True, f"daemon is listening on {sock_path}"


def check_dir_perms() -> CheckResult:
    problems = paths.check_perms(paths.base_dir(), paths.DIR_MODE)
    if problems:
        return False, "; ".join(problems)
    return True, f"{paths.base_dir()} is {oct(paths.DIR_MODE)} and owned by us"


def check_socket_perms() -> CheckResult:
    sock_path = paths.socket_path()
    if not sock_path.exists():
        return False, f"{sock_path} does not exist yet"
    problems = paths.check_perms(sock_path, paths.FILE_MODE)
    if problems:
        return False, "; ".join(problems)
    return True, f"{sock_path} is {oct(paths.FILE_MODE)} and owned by us"


def check_totp_secret() -> CheckResult:
    path = paths.totp_secret_path()
    problems = paths.check_perms(path, paths.FILE_MODE)
    if problems:
        return False, "; ".join(problems) + " -- run the enrollment script first if missing"
    return True, f"{path} is {oct(paths.FILE_MODE)} and owned by us"


def check_tty_tickets() -> CheckResult:
    try:
        result = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"could not run `sudo -n -l`: {exc}"

    if result.returncode != 0:
        return False, (
            "cannot verify without an active sudo timestamp -- run `sudo -v` "
            "once interactively as yourself, then re-run doctor"
        )

    output = result.stdout
    if "!tty_tickets" in output or "timestamp_type=global" in output:
        return True, "!tty_tickets (or timestamp_type=global) is set"

    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "<user>"
    return False, (
        "missing `Defaults !tty_tickets` (or `timestamp_type=global`) -- without it, "
        "the daemon's own `sudo -v` timestamp is invisible to the agent's separate "
        "session, and every request will deny at the askpass safety-net step. Add via:\n"
        "    sudo visudo -f /etc/sudoers.d/agent-sudo\n"
        f"and add the line: Defaults:{user} !tty_tickets\n"
        "(visudo validates syntax before saving, so a typo can't leave sudoers broken --"
        " unlike piping into the file with tee, which writes first and validates after)"
    )


def check_askpass_consulted() -> CheckResult:
    # Deliberately resets the cached sudo timestamp (-k) so this check forces
    # a real credential decision rather than riding an existing cache. This is
    # a diagnostic side effect the human should expect from running `doctor`.
    env = os.environ.copy()
    env["SUDO_ASKPASS"] = "/bin/false"
    try:
        result = subprocess.run(
            ["sudo", "-A", "-k", "true"], env=env, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"could not run `sudo -A -k true`: {exc}"

    if result.returncode == 0:
        return False, (
            "`sudo -A true` succeeded even with a broken askpass (/bin/false) -- NOPASSWD "
            "may be set for this command, which would defeat this tool's entire premise"
        )
    return True, "askpass is consulted as expected (a broken askpass correctly fails sudo)"


def build_checks(credential_mode: str) -> list[tuple[str, callable]]:
    checks: list[tuple[str, callable]] = [
        ("daemon socket reachable", check_daemon_reachable),
        ("~/.agent-sudo directory permissions", check_dir_perms),
        ("socket file permissions", check_socket_perms),
    ]
    if credential_mode == "timestamp":
        checks.append(("TOTP secret permissions", check_totp_secret))
        checks.append(("!tty_tickets / timestamp_type=global", check_tty_tickets))
    checks.append(("askpass is actually consulted (no NOPASSWD bypass)", check_askpass_consulted))
    return checks


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="agent-sudo doctor")
    parser.add_argument("--credential-mode", choices=["relay", "timestamp"], default="relay")
    args = parser.parse_args(argv)

    all_ok = True
    for name, check in build_checks(args.credential_mode):
        try:
            ok, message = check()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            ok, message = False, f"check raised {exc!r}"  # a check crashing is itself a FAIL
        all_ok = all_ok and ok
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name}: {message}", file=sys.stdout)

    raise SystemExit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
