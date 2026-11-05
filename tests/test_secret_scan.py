import subprocess
from pathlib import Path

import pytest

from scripts import ci, docker_job


def repository(path, *, commit=True):
    path.mkdir()
    subprocess.run(["git", "init", "--quiet", str(path)], check=True)
    (path / ".gitignore").write_text(".ci-tmp/\nreports/\n.env\n")
    (path / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
    (path / "tracked.py").write_text("print('first revision')\n")
    (path / "ignored.env").write_text("untracked source must be scanned")
    (path / ".env").write_text("ignored configuration must not be copied")
    if commit:
        subprocess.run(["git", "add", ".gitignore", ".gitleaks.toml", "tracked.py"], cwd=path, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=CI Test",
                "-c",
                "user.email=ci@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "first revision",
            ],
            cwd=path,
            check=True,
        )
    (path / ".ci-tmp").mkdir()
    return path


@pytest.mark.parametrize("defect", ["missing_refs", "unborn", "shallow", "missing_object"])
def test_secret_scan_fails_closed_before_scanner_on_invalid_history(tmp_path, monkeypatch, defect):
    source = repository(tmp_path / "source", commit=defect != "unborn")
    if defect == "missing_refs":
        (source / ".git/refs").rename(source / ".git/unusable-refs")
    elif defect == "shallow":
        clone = tmp_path / "shallow"
        subprocess.run(["git", "clone", "--quiet", "--depth=1", source.as_uri(), str(clone)], check=True)
        source = clone
    elif defect == "missing_object":
        blob = subprocess.check_output(["git", "rev-parse", "HEAD:tracked.py"], cwd=source).decode().strip()
        (source / ".git/objects" / blob[:2] / blob[2:]).unlink()
    reports = source / "reports"
    reports.mkdir()
    for name in ("gitleaks.json", "gitleaks-working-tree.json"):
        (reports / name).write_text("[]")
    monkeypatch.setattr(ci, "ROOT", source)
    monkeypatch.setattr(ci, "docker", lambda *a, **kw: pytest.fail("Invalid history must not reach scanner"))
    with pytest.raises(RuntimeError, match="Git checkout") as error:
        ci.secrets_check()
    assert "ignored configuration" not in str(error.value)
    assert list(reports.iterdir()) == []


def test_packed_detached_transfer_still_scans_full_history_and_nonignored_worktree(tmp_path, monkeypatch):
    import io
    import tarfile

    source = repository(tmp_path / "source")
    subprocess.run(["git", "pack-refs", "--all", "--prune"], cwd=source, check=True)
    subprocess.run(["git", "checkout", "--quiet", "--detach", "HEAD"], cwd=source, check=True)
    # Real CI source transfer rejects secret-like files even when untracked;
    # retain a normal untracked source file instead of this helper's .env suffix.
    (source / "ignored.env").rename(source / "untracked.py")
    monkeypatch.setattr(docker_job, "ROOT", source)
    archive = io.BytesIO()
    docker_job.archive_source(archive)
    restored = tmp_path / "restored"
    with tarfile.open(fileobj=archive) as files:
        files.extractall(restored, filter="data")
    (restored / ".ci-tmp").mkdir()
    monkeypatch.setattr(ci, "ROOT", restored)
    modes = []

    def scanner(arguments, **kwargs):
        mode = arguments[arguments.index(ci.GITLEAKS_IMAGE) + 1]
        modes.append(mode)
        assert "--redact=100" in arguments and arguments[arguments.index("--network") + 1] == "none"
        mount = next(a for a in arguments if a.startswith("type=bind,source=") and "target=/repo," in a)
        root = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
        assert not (root / ".env").exists()
        if mode == "git":
            assert (root / ".git/refs").is_dir()
            assert b"first revision" in subprocess.check_output(
                ["git", "log", "--all", "--format=%s"], cwd=root
            )
        else:
            assert (root / "tracked.py").exists() and (root / "untracked.py").exists()
            assert not (root / ".git").exists()

    monkeypatch.setattr(ci, "docker", scanner)
    ci.secrets_check()
    assert modes == ["git", "dir"]
