"""A hostile or careless project directory: secrets, caches, virtual environments,
links and junctions, unsafe names. Nothing here touches the server."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from udcs_client.check import check_offline
from udcs_client.output import Exit
from udcs_client.select import select_files

SPEC_ALL = """
[project]
name = "demo"
version = "1.0"

[entry]
script = "main.py"

[files]
include = {include}
"""


def _spec(include: str) -> str:
    return SPEC_ALL.format(include=include)


def _junction(link, target) -> None:
    cmd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    subprocess.run(  # noqa: S603 -- fixed system binary, test-controlled paths
        [cmd, "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True
    )


def test_deny_list_drops_secrets_caches_and_venvs(h, tmp_path):
    root = h.write_project(
        tmp_path / "p",
        {
            "main.py": "print(1)",
            ".env": "TOKEN=abc",
            "config/.env.local": "X=1",
            "keys/server.pem": "-----BEGIN CERTIFICATE-----",
            "id_rsa": "x",
            "credentials-prod.json": "{}",
            "__pycache__/main.cpython-312.pyc": b"\0",
            ".git/config": "[core]",
            "myvenv/pyvenv.cfg": "home = x",
            "myvenv/Lib/site.py": "import os",
            "udcs-results/old/out.py": "1",
        },
        _spec('["**"]'),
    )
    selection = select_files(root, ["**"], [])
    assert [rel for rel, _ in selection.files] == ["main.py"]
    assert not selection.problems
    assert selection.excluded["virtual environment"] == 1
    assert selection.excluded["secret or cache file"] >= 4


def test_naming_a_denied_file_explicitly_is_an_error_not_a_silent_drop(h, tmp_path):
    root = h.write_project(
        tmp_path / "p", {"main.py": "1", ".env": "A=1"}, _spec('["main.py", ".env"]')
    )
    report = check_offline(root)
    assert any(".env is never packaged" in p for p in report.problems)


def test_secret_heuristic_blocks_and_allow_flagged_overrides(h, tmp_path):
    files = {"main.py": "1", "settings.py": 'password = "hunter22hunter"\n'}
    root = h.write_project(tmp_path / "p", files, _spec('["**/*.py"]'))
    report = check_offline(root)
    assert any("settings.py" in p and "heuristic" in p for p in report.problems)
    root2 = h.write_project(
        tmp_path / "p2",
        files,
        _spec('["**/*.py"]') + 'allow_flagged = ["settings.py"]\n',
    )
    assert check_offline(root2).ok


@pytest.mark.parametrize(
    "secret",
    [
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE",
        "aws = 'AKIAABCDEFGHIJKLMNOP'",
        "t = 'ghp_" + "a" * 36 + "'",
        "s = 'xoxb-1234567890-abcdef'",
    ],
)
def test_common_secret_shapes_are_flagged(h, tmp_path, secret):
    root = h.write_project(
        tmp_path / "p", {"main.py": "1", "leak.py": secret}, _spec('["**/*.py"]')
    )
    assert not check_offline(root).ok


@pytest.mark.parametrize(
    ("name", "why"),
    [
        ("CON.py", "reserved"),
        ("e\u0301.py", "NFC"),
        ("a" * 120 + ".py", "long"),
    ],
)
def test_unsafe_file_names_are_reported_not_renamed(h, tmp_path, name, why):
    try:
        root = h.write_project(tmp_path / "p", {"main.py": "1", name: "x"}, _spec('["**/*.py"]'))
    except OSError:
        pytest.skip(f"this filesystem cannot even create {why} names")
    report = check_offline(root)
    assert not report.ok and report.problems


def test_entry_must_be_selected(h, tmp_path):
    root = h.write_project(tmp_path / "p", {"main.py": "1", "lib.py": "2"}, _spec('["lib.py"]'))
    report = check_offline(root)
    assert any("entry.script" in p for p in report.problems)


def test_unknown_spec_keys_are_errors(h, tmp_path, run):
    root = h.write_project(
        tmp_path / "p", {"main.py": "1"}, _spec('["main.py"]') + "\n[surprise]\nx = 1\n"
    )
    result = run("check", "--offline", "-C", str(root))
    assert result.code == Exit.INVALID and "surprise" in result.err


def test_oversized_spec_is_refused(h, tmp_path, run):
    root = h.write_project(tmp_path / "p", {"main.py": "1"}, _spec('["main.py"]') + "#" * 70_000)
    result = run("check", "--offline", "-C", str(root))
    assert result.code == Exit.INVALID and "larger than" in result.err


def test_pattern_matching_nothing_is_a_warning(h, tmp_path, run):
    root = h.write_project(tmp_path / "p", {"main.py": "1"}, _spec('["main.py", "data/*.json"]'))
    result = run("check", "--offline", "-C", str(root))
    assert result.code == 0 and "matches no file" in result.err


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions")
def test_a_junction_out_of_the_project_is_refused(h, tmp_path):
    secrets = tmp_path / "home" / ".ssh"
    secrets.mkdir(parents=True)
    (secrets / "notes.py").write_text("PRIVATE = 1")
    root = h.write_project(tmp_path / "p", {"main.py": "1"}, _spec('["**/*.py"]'))
    _junction(root / "linked", secrets.parent)
    report = check_offline(root)
    assert any("link or junction" in p for p in report.problems)
    assert report.manifest is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks need no privilege")
def test_a_symlinked_file_is_refused(h, tmp_path):
    outside = tmp_path / "secret.py"
    outside.write_text("KEY = 1")
    root = h.write_project(tmp_path / "p", {"main.py": "1"}, _spec('["**/*.py"]'))
    os.symlink(outside, root / "link.py")
    report = check_offline(root)
    assert any("link" in p for p in report.problems)
