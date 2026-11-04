"""Guard Debian console logout for a dedicated native shell runner.

Standalone stdlib operator tool. Check-only unless --apply is explicit. Changes
only the known clear_console condition; never reads runner credentials/config.
"""

from __future__ import annotations

import argparse
import os
import stat
import tempfile
import time
from pathlib import Path

ORIGINAL = """if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi"""
GUARDED = """if [ "$SHLVL" = 1 ] && [ -t 0 ] && [ -t 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi"""


def patch_logout(source: str) -> str:
    if source.count(GUARDED) == 1 and ORIGINAL not in source:
        return source
    if source.count(ORIGINAL) != 1 or GUARDED in source:
        raise ValueError("Unsupported logout profile; review manually, no changes made")
    return source.replace(ORIGINAL, GUARDED, 1)


def configure(home: Path, *, apply: bool = False) -> bool:
    if not home.is_absolute() or home.is_symlink() or not home.is_dir():
        raise ValueError("Specify the dedicated runner's existing absolute home directory")
    path = home / ".bash_logout"
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != home.stat().st_uid
        or metadata.st_mode & 0o7000
    ):
        raise ValueError("Requires an ordinary logout file owned by the runner home owner")
    original = path.read_text()
    replacement = patch_logout(original)
    if replacement == original:
        print("Console logout already guarded for non-interactive CI shells")
        return False
    if not apply:
        print("Known Debian logout found; --apply will guard console access and keep a private backup")
        return False
    backup = path.with_name(path.name + ".backup." + str(time.time_ns()))
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        if os.geteuid() == 0:
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor, temporary = tempfile.mkstemp(prefix=".bash_logout-", dir=home)
    try:
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            if os.geteuid() == 0:
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        current = path.lstat()
        identity = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink")
        if any(getattr(current, field) != getattr(metadata, field) for field in identity):
            raise ValueError("Logout file changed concurrently; refusing to overwrite")
        if path.read_text() != original:
            raise ValueError("Logout file changed concurrently; refusing to overwrite")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    print("Console logout guarded atomically; private backup kept, no service restart required")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        configure(args.home, apply=args.apply)
    except (OSError, ValueError):
        raise SystemExit("Shell profile check/update failed; inspect the dedicated home privately") from None


if __name__ == "__main__":
    main()
