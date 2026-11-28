"""E1 probe identity: never a name, and never able to break the probe.

On 2026-11-28 a pywin32-based identity lookup raised ImportError in every E1 child worker
(`python -I` does not put pywin32's DLLs on the search path), so the children wrote no
result. The first test runs the probe exactly the way gpu_matrix launches its children.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows token APIs")


def test_probe_writes_a_result_when_launched_like_an_e1_child(tmp_path):
    from udcs_agent.diagnostics import gpu_matrix

    out = tmp_path / "child.json"
    argv = gpu_matrix._bootstrap(out)
    assert argv[1:3] == ["-I", "-B"]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=120, cwd=tmp_path)  # noqa: S603
    assert out.exists(), f"no result (exit {r.returncode}): {r.stderr[-600:]}"
    result = json.loads(out.read_text(encoding="utf-8"))
    # CUDA may be absent on a CI runner (ok is then False); the identity must still be there.
    assert result["account"] in ("<user>", "NT AUTHORITY\\SYSTEM")


def test_account_labels(monkeypatch):
    from udcs_agent.diagnostics import gpu_probe

    monkeypatch.setenv("USERNAME", "LABPC-042$")
    monkeypatch.setattr(gpu_probe, "_is_local_system", lambda: True)
    assert gpu_probe._account() == "NT AUTHORITY\\SYSTEM"
    monkeypatch.setattr(gpu_probe, "_is_local_system", lambda: False)
    assert gpu_probe._account() == "<user>"
    monkeypatch.setattr(gpu_probe, "_is_local_system", lambda: None)
    assert gpu_probe._account() == "<unknown>"

    def broken():
        raise ImportError("DLL load failed while importing win32api")

    monkeypatch.setattr(gpu_probe, "_is_local_system", broken)
    assert gpu_probe._account() == "<unknown>"


def test_real_token_is_not_local_system_in_the_test_process():
    from udcs_agent.diagnostics import gpu_probe

    assert gpu_probe._is_local_system() is False  # tests never run as SYSTEM
