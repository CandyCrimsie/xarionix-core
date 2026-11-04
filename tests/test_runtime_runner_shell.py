import os
import shutil
import subprocess

import pytest

from scripts import configure_runtime_shell as shell


def test_guard_is_narrow_preserves_surrounding_profile_and_is_idempotent():
    source = "# Distribution profile\n\n" + shell.ORIGINAL + "\n# Preserve this comment\n"
    patched = shell.patch_logout(source)
    assert patched == source.replace(shell.ORIGINAL, shell.GUARDED)
    assert shell.patch_logout(patched) == patched


@pytest.mark.parametrize("source", ["", "custom logout", shell.ORIGINAL * 2, shell.GUARDED * 2])
def test_unknown_or_ambiguous_logout_requires_manual_review(source):
    with pytest.raises(ValueError, match="Unsupported"):
        shell.patch_logout(source)


def test_check_does_not_mutate_and_apply_retains_permissions_and_private_backup(tmp_path):
    path = tmp_path / ".bash_logout"
    path.write_text(shell.ORIGINAL + "\n")
    path.chmod(0o640)
    before = path.stat()
    assert shell.configure(tmp_path) is False
    assert path.read_text() == shell.ORIGINAL + "\n"
    assert list(tmp_path.glob(".bash_logout.backup.*")) == []
    assert shell.configure(tmp_path, apply=True) is True
    assert path.read_text() == shell.GUARDED + "\n"
    assert path.stat().st_mode & 0o777 == 0o640
    assert (path.stat().st_uid, path.stat().st_gid) == (before.st_uid, before.st_gid)
    backups = list(tmp_path.glob(".bash_logout.backup.*"))
    assert len(backups) == 1 and backups[0].read_text() == shell.ORIGINAL + "\n"
    assert backups[0].stat().st_mode & 0o777 == 0o600
    assert backups[0].stat().st_uid == before.st_uid
    assert shell.configure(tmp_path, apply=True) is False
    assert list(tmp_path.glob(".bash_logout.backup.*")) == backups


def test_symlinked_home_or_logout_is_refused(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "outside"
    target.write_text(shell.ORIGINAL)
    (home / ".bash_logout").symlink_to(target)
    with pytest.raises(ValueError, match="ordinary logout"):
        shell.configure(home, apply=True)
    alias = tmp_path / "alias"
    alias.symlink_to(home, target_is_directory=True)
    with pytest.raises(ValueError, match="absolute home"):
        shell.configure(alias, apply=True)
    assert target.read_text() == shell.ORIGINAL


def test_concurrent_edit_is_preserved_instead_of_overwritten(tmp_path, monkeypatch):
    path = tmp_path / ".bash_logout"
    path.write_text(shell.ORIGINAL)
    original_mkstemp = shell.tempfile.mkstemp

    def concurrent_edit(*args, **kwargs):
        result = original_mkstemp(*args, **kwargs)
        path.write_text("Changed by operator")
        return result

    monkeypatch.setattr(shell.tempfile, "mkstemp", concurrent_edit)
    with pytest.raises(ValueError, match="concurrently"):
        shell.configure(tmp_path, apply=True)
    assert path.read_text() == "Changed by operator"
    assert list(tmp_path.glob(".bash_logout-*")) == []


@pytest.mark.parametrize(
    "guarded,command,expected", [(False, "exit 0", 73), (True, "exit 0", 0), (True, "exit 42", 42)]
)
def test_noninteractive_logout_without_tty_and_real_failure_propagation(tmp_path, guarded, command, expected):
    # A failing console shim is portable across macOS and Linux, requires no VT,
    # and does not touch /usr/bin or any real user's shell profile.
    console = tmp_path / "clear-console"
    console.write_text("#!/bin/sh\nprintf 'CONSOLE-CALLED\\n'\nexit 73\n")
    console.chmod(0o700)
    source = shell.patch_logout(shell.ORIGINAL) if guarded else shell.ORIGINAL
    profile = tmp_path / "logout"
    profile.write_text(source.replace("/usr/bin/clear_console", str(console)))
    bash = shutil.which("bash")
    assert bash is not None, "The project's shell checks require Bash"
    result = subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            "-c",
            'set -eo pipefail; SHLVL=1; . "$1"; ' + command,
            "--",
            str(profile),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env={"PATH": os.defpath},
        timeout=10,
    )
    assert result.returncode == expected
    assert ("CONSOLE-CALLED" in result.stdout) is (not guarded)
