"""m15_service_acceptance.ps1 safeguards, exercised through its read-only -Preflight mode.

-Preflight needs no elevation, installs nothing and writes nothing: these tests point it
at a temporary -EvidenceRoot and check which file each pass would write and when it
refuses. They cannot cover the 'UDCSAgent already installed' refusal unless the service
is installed on the test machine (then pass 1 must refuse, which is asserted).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell script")

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "acceptance" / "m15_service_acceptance.ps1"
RETIRED = ROOT / "docs" / "acceptance" / "data" / "m15-service-acceptance.json"
SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
POWERSHELL = SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def _run(*argv: str) -> subprocess.CompletedProcess:
    # Fixed executables by absolute path, fixed arguments plus test-owned paths.
    return subprocess.run(argv, capture_output=True, text=True, timeout=120)  # noqa: S603


def _ps(*args: str) -> subprocess.CompletedProcess:
    return _run(str(POWERSHELL), "-NoProfile", "-ExecutionPolicy", "Bypass", *args)


def _service_installed() -> bool:
    return _run(str(SYSTEM32 / "sc.exe"), "query", "UDCSAgent").returncode == 0


def _preflight(root: Path, *extra: str) -> tuple[int, dict]:
    r = _ps("-File", str(SCRIPT), "-Preflight", "-EvidenceRoot", str(root), *extra)
    assert r.returncode in (0, 2), r.stdout + r.stderr
    return r.returncode, json.loads(r.stdout)


def _label() -> str:
    from udcs_agent.diagnostics.context import machine_label

    return machine_label()["label"]


def _tree(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }


def _write_report(root: Path, label: str, report: dict) -> Path:
    path = root / "machines" / label / "m15-service-acceptance.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_label_matches_the_agents_machine_label(tmp_path):
    _code, out = _preflight(tmp_path)
    assert out["machine_label"] == _label()


def test_pass1_targets_a_machine_directory_and_never_the_retired_record(tmp_path):
    shutil.copy(RETIRED, tmp_path / "m15-service-acceptance.json")  # history present
    before = _tree(tmp_path)
    code, out = _preflight(tmp_path)
    target = Path(out["target"])
    assert target == tmp_path / "machines" / _label() / "m15-service-acceptance.json"
    assert target != tmp_path / "m15-service-acceptance.json"
    assert _tree(tmp_path) == before, "preflight must write nothing"
    if _service_installed():
        assert code == 2 and "already installed" in out["reason"]
    else:
        assert code == 0 and out["would_refuse"] is False


def test_pass1_refuses_when_this_machines_report_holds_evidence(tmp_path):
    _write_report(tmp_path, _label(), {"checks": {"service_starts": {"pass": True}}})
    code, out = _preflight(tmp_path)
    assert code == 2 and out["would_refuse"] is True
    if not _service_installed():
        assert "already holds pass-1 evidence" in out["reason"]


def test_replace_evidence_is_required_to_start_over(tmp_path):
    _write_report(tmp_path, _label(), {"reboot_marker": {"boot_before": "2026-01-01T00:00:00"}})
    code, out = _preflight(tmp_path, "-ReplaceEvidence")
    if _service_installed():
        assert code == 2
    else:
        assert code == 0 and out["would_refuse"] is False


def test_pass2_refuses_without_a_pass1_record_for_this_machine(tmp_path):
    shutil.copy(RETIRED, tmp_path / "m15-service-acceptance.json")  # has a reboot_marker
    code, out = _preflight(tmp_path, "-AfterReboot")
    assert code == 2 and "no pass-1 record" in out["reason"]


def test_pass2_refuses_a_report_recorded_on_another_machine(tmp_path):
    # A report copied into this machine's directory, but recorded elsewhere.
    _write_report(
        tmp_path,
        _label(),
        {
            "machine": {"label": "000000000000", "build": "10.0.22000.0", "gpu": ["GT 730"]},
            "reboot_marker": {"boot_before": "2000-01-01T00:00:00"},
        },
    )
    code, out = _preflight(tmp_path, "-AfterReboot")
    assert code == 2 and "not recorded on this machine" in out["reason"]


def _facts() -> dict:
    helper = ROOT / "tools" / "acceptance" / "evidence_paths.ps1"
    r = _ps("-Command", f". '{helper}'; Get-MachineFacts | ConvertTo-Json -Depth 4")
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_machine_facts_record_the_hardware_but_not_the_host_name():
    import socket

    facts = _facts()
    assert facts["label"] == _label()
    for field in ("edition", "build", "build_ubr", "cpu", "cores", "logical", "ram_gib", "gpu"):
        assert facts[field], field
    assert socket.gethostname().lower() not in json.dumps(facts).lower()


def test_pass2_proceeds_only_on_this_machine_after_a_reboot(tmp_path):
    facts = _facts()
    path = _write_report(
        tmp_path,
        _label(),
        {"machine": facts, "reboot_marker": {"boot_before": "2000-01-01T00:00:00"}},
    )
    code, out = _preflight(tmp_path, "-AfterReboot")
    assert code == 0 and out["would_refuse"] is False, out

    # Same machine, but no reboot since the marker: refused.
    path.write_text(
        json.dumps({"machine": facts, "reboot_marker": {"boot_before": "2999-01-01T00:00:00"}}),
        encoding="utf-8",
    )
    code, out = _preflight(tmp_path, "-AfterReboot")
    assert code == 2 and "not rebooted" in out["reason"]


def test_pass2_tolerates_a_gpu_driver_update_across_the_reboot(tmp_path):
    facts = _facts()
    facts["gpu"] = [g.rsplit(" (", 1)[0] + " (0.0.0.1)" for g in facts["gpu"]]  # older driver
    _write_report(
        tmp_path,
        _label(),
        {"machine": facts, "reboot_marker": {"boot_before": "2000-01-01T00:00:00"}},
    )
    code, out = _preflight(tmp_path, "-AfterReboot")
    assert code == 0 and out["would_refuse"] is False, out


def test_evidence_root_is_refused_outside_preflight(tmp_path):
    r = _ps("-File", str(SCRIPT), "-EvidenceRoot", str(tmp_path))
    assert r.returncode != 0 and "only for -Preflight" in (r.stdout + r.stderr)
    assert not any(tmp_path.iterdir())
