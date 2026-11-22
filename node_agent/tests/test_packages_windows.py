"""Reparse-point (junction) attacks against packing, staging, outputs and cleanup.

Junctions need no privilege to create, which makes them the realistic escape primitive
for a workload or a hostile package author on Windows.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import uuid

import pytest

from udcs_agent.packages import (
    NodeCache,
    VerificationError,
    collect_outputs,
    manifest_from_dir,
    remove_staging,
    stage_package,
    staging_dir,
)
from udcs_shared.packages import PackageManifest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions")


def _junction(link, target) -> None:
    cmd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    subprocess.run(  # noqa: S603 -- fixed system binary, test-controlled paths
        [cmd, "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
    )


def _package(cache: NodeCache, files: dict[str, bytes]) -> PackageManifest:
    entries = []
    for path, data in sorted(files.items()):
        digest = hashlib.sha256(data).hexdigest()
        blob = cache.path(digest)
        blob.parent.mkdir(parents=True, exist_ok=True)
        blob.write_bytes(data)
        entries.append({"path": path, "sha256": digest, "size": len(data)})
    return PackageManifest.model_validate(
        {
            "schema_version": 1,
            "kind": "package",
            "name": "p",
            "version": "1",
            "files": entries,
            "entry": {"script": entries[0]["path"]},
        }
    )


def test_packer_refuses_junctions_and_builds_deterministic_manifests(tmp_path):
    src = tmp_path / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "main.py").write_text("print(1)")
    (src / "pkg" / "mod.py").write_text("x = 1")
    first, _ = manifest_from_dir(src, name="p", version="1", entry="main.py")
    second, _ = manifest_from_dir(src, name="p", version="1", entry="main.py")
    assert first.digest() == second.digest()
    assert [f.path for f in first.files] == ["main.py", "pkg/mod.py"]
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "id_rsa").write_text("PRIVATE")
    _junction(src / "escape", secrets)
    with pytest.raises(VerificationError, match="reparse"):
        manifest_from_dir(src, name="p", version="1", entry="main.py")


def test_staging_is_unique_read_only_and_verified(tmp_path):
    cache = NodeCache(tmp_path)
    package = _package(cache, {"main.py": b"print(1)", "lib/util.py": b"y = 2"})
    job = str(uuid.uuid4())
    staged = stage_package(tmp_path, job, 1, package, {}, cache)
    again = stage_package(tmp_path, job, 2, package, {}, cache)
    assert staged.root != again.root  # per attempt
    assert (staged.source / "lib" / "util.py").read_bytes() == b"y = 2"
    with pytest.raises(PermissionError):
        (staged.source / "main.py").write_text("tampered")  # read-only attribute
    remove_staging(staged.root)
    remove_staging(again.root)
    assert not staged.root.exists() and not again.root.exists()


def test_staging_refuses_a_junctioned_staging_directory(tmp_path):
    cache = NodeCache(tmp_path)
    package = _package(cache, {"main.py": b"print(1)"})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "staging").mkdir()
    job = str(uuid.uuid4())
    # An attacker who could write the data directory pre-plants the attempt's directory.
    _junction(staging_dir(tmp_path, job, 1), elsewhere)
    try:
        staged = stage_package(tmp_path, job, 1, package, {}, cache)
    except VerificationError:
        staged = None
    # Either the junction was removed and a real directory created, or staging refused;
    # in no case did anything get written into the junction's target.
    assert not any(elsewhere.iterdir())
    if staged is not None:
        assert staged.root.is_dir() and not staged.root.is_junction()


def test_outputs_refuse_junctions_and_enforce_limits_early(tmp_path):
    out = tmp_path / "out"
    (out / "sub").mkdir(parents=True)
    (out / "a.txt").write_bytes(b"1" * 10)
    (out / "sub" / "b.txt").write_bytes(b"2" * 10)
    manifest, _ = collect_outputs(
        out, attempt=1, snapshot_dir=tmp_path / "snap", max_files=5, max_bytes=100
    )
    assert [f.path for f in manifest.files] == ["a.txt", "sub/b.txt"]
    with pytest.raises(VerificationError, match="more than 1"):
        collect_outputs(out, attempt=1, snapshot_dir=tmp_path / "snap", max_files=1, max_bytes=100)
    with pytest.raises(VerificationError, match="exceed 15"):
        collect_outputs(out, attempt=1, snapshot_dir=tmp_path / "snap", max_files=5, max_bytes=15)
    private = tmp_path / "private"
    private.mkdir()
    (private / "student.docx").write_bytes(b"homework")
    _junction(out / "loot", private)
    with pytest.raises(VerificationError, match="reparse point"):
        collect_outputs(out, attempt=1, snapshot_dir=tmp_path / "snap", max_files=5, max_bytes=100)


def _collect(out, snap, **limits):
    limits = {"max_files": 50, "max_bytes": 10_000, **limits}
    return collect_outputs(out, attempt=1, snapshot_dir=snap, **limits)


def test_outputs_refuse_hard_links(tmp_path):
    """A hard link in out/ would export a file from elsewhere on the volume."""
    out = tmp_path / "out"
    out.mkdir()
    secret = tmp_path / "student.docx"
    secret.write_bytes(b"homework")
    os.link(secret, out / "innocent.txt")
    with pytest.raises(VerificationError, match="hard-linked"):
        _collect(out, tmp_path / "snap")
    assert not (tmp_path / "snap").exists()  # nothing half-collected is left


def test_outputs_check_the_open_handle_not_the_path(tmp_path, monkeypatch):
    """The race: a directory passes the path check, then is swapped for a junction
    before its files are read. Simulated by disabling the path check entirely; the
    handle check must still refuse the file, because its final path is outside out/."""
    import udcs_agent.packages as packages

    out = tmp_path / "out"
    out.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    (private / "id_rsa").write_bytes(b"PRIVATE KEY")
    _junction(out / "swapped", private)
    monkeypatch.setattr(packages, "_is_reparse", lambda _path: False)
    with pytest.raises(VerificationError, match="outside the output directory"):
        _collect(out, tmp_path / "snap")


def test_outputs_are_copied_privately_and_hash_what_was_copied(tmp_path):
    out = tmp_path / "out"
    (out / "d").mkdir(parents=True)
    (out / "d" / "r.csv").write_bytes(b"1,2\n")
    manifest, paths = _collect(out, tmp_path / "snap")
    [item] = manifest.files
    copy = paths["d/r.csv"]
    assert copy.parent == tmp_path / "snap" and copy.read_bytes() == b"1,2\n"
    assert item.sha256 == hashlib.sha256(b"1,2\n").hexdigest()
    (out / "d" / "r.csv").write_bytes(b"changed later")  # the workload rewrites it
    assert copy.read_bytes() == b"1,2\n"  # the upload reads the snapshot


def test_output_walk_is_bounded_in_entries_and_depth(tmp_path):
    out = tmp_path / "out"
    deep = out
    for i in range(6):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    with pytest.raises(VerificationError, match="deeper than 4"):
        _collect(out, tmp_path / "snap", max_depth=4)
    wide = tmp_path / "wide"
    for i in range(30):
        (wide / f"empty{i}").mkdir(parents=True)  # directories, not files, but still walked
    with pytest.raises(VerificationError, match="more than 10 entries"):
        _collect(wide, tmp_path / "snap2", max_entries=10)


def test_cleanup_never_changes_a_hard_link_target(tmp_path):
    """remove_staging used to clear the read-only attribute before deleting, which
    changes it on every other name of a hard-linked file too."""
    import stat

    root = tmp_path / "staging" / "job-1"
    (root / "src").mkdir(parents=True)
    outside = tmp_path / "admin-config.ini"
    outside.write_bytes(b"locked=1")
    os.chmod(outside, stat.S_IREAD)
    os.link(outside, root / "src" / "linked.ini")
    (root / "src" / "own.py").write_bytes(b"x")
    os.chmod(root / "src" / "own.py", stat.S_IREAD)
    remove_staging(root)
    assert not root.exists()
    assert outside.read_bytes() == b"locked=1"
    assert not os.stat(outside).st_mode & stat.S_IWRITE  # still read-only
    os.chmod(outside, stat.S_IWRITE)  # let pytest clean up


def test_cleanup_never_deletes_through_a_junction(tmp_path):
    root = tmp_path / "staging" / "job-1"
    (root / "out").mkdir(parents=True)
    victim = tmp_path / "student-files"
    victim.mkdir()
    (victim / "thesis.docx").write_bytes(b"years of work")
    _junction(root / "out" / "link", victim)
    remove_staging(root)
    assert not root.exists()
    assert (victim / "thesis.docx").read_bytes() == b"years of work"
