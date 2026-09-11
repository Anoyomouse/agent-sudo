#!/usr/bin/env python3
"""One-shot TOTP enrollment for the agent-sudo approval daemon.

Run this once, on the machine that will run the daemon, before starting
`agent-sudo-daemon` for the first time. Scan the printed otpauth:// URI (or
enter the secret manually) into an authenticator app. Refuses to overwrite
an existing enrollment -- delete the secret file yourself first if you
really want to re-enroll.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Must follow sys.path.insert above, since this script can run uninstalled
# (before `pip install -e .`).
from agent_sudo import paths, totp  # noqa: E402  pylint: disable=wrong-import-position


def main() -> None:
    paths.ensure_base_dir()
    secret_path = paths.totp_secret_path()
    if secret_path.exists():
        print(
            f"error: {secret_path} already exists -- refusing to overwrite an existing enrollment",
            file=sys.stderr,
        )
        raise SystemExit(1)

    username = getpass.getuser()
    secret, uri = totp.provision(secret_path, username=username)

    print(f"TOTP secret written to {secret_path} (0600)\n")
    print("Scan this into an authenticator app:\n")
    try:
        import qrcode  # pylint: disable=import-outside-toplevel  # optional, may not be installed

        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make()
        qr.print_ascii(invert=True)
    except ImportError:
        print("(install the 'enroll' extra for a scannable QR code: pip install agent-sudo[enroll])")

    print(f"\nManual entry secret: {secret}")
    print(f"otpauth URI: {uri}")


if __name__ == "__main__":
    main()
