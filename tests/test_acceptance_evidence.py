"""Acceptance evidence folder must never hold diagnostic results, and must keep history."""

import hashlib
import json
import re
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / "docs" / "acceptance" / "data"

# The retired build 22000 machine's records (2026-11-22, commit 042f5bb). That machine no
# longer exists, so these can never be re-measured: any change to them is a bug.
# SHA-256 of the content with CRLF normalised to LF (core.autocrlf rewrites line endings).
RETIRED = {
    "m15-service-acceptance.json": (
        "e9d5c24d3d85c45cc507c410147eb8d6f99d65db1a3082fa96947bed12db25ea"
    ),
    "m2-isolation-service.json": (
        "31b8e283f50accfb1a5e72c7273475cca01709c043df63b608ed737baac63154"
    ),
}


def _files():
    return sorted(EVIDENCE.rglob("*.json"))


def test_retired_machine_evidence_is_unchanged():
    for name, digest in RETIRED.items():
        data = (EVIDENCE / name).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(data).hexdigest() == digest, f"{name} (retired machine) changed"


def test_no_diagnostic_results_in_evidence_folder():
    for path in _files():
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            assert data.get("evidence") is not False, f"{path.name} is labelled diagnostic"
            assert data.get("kind") not in ("preflight", "m15-preflight"), (
                f"{path.name} is a preflight diagnostic"
            )


def test_machine_evidence_is_labelled_and_never_names_the_host():
    for path in (EVIDENCE / "machines").glob("*/m15-service-acceptance.json"):
        label = path.parent.name
        assert re.fullmatch(r"[0-9a-f]{12}", label), path
        machine = json.loads(path.read_text(encoding="utf-8-sig"))["machine"]
        assert machine["label"] == label, path
        assert "host" not in machine, f"{path}: the host name must not be recorded"
        for field in ("edition", "build", "cpu", "ram_gib", "gpu"):
            assert machine.get(field), f"{path}: machine.{field} missing"


def test_exposure_summaries_in_evidence_folder_are_localsystem():
    for path in EVIDENCE.rglob("m3-exposure-audit-*.json"):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        assert data.get("evidence") is True, path.name
        assert data["identity"]["context"] == "localsystem", path.name
        # LocalSystem's USERNAME is HOSTNAME$: a trailing $ means the host name leaked.
        assert not str(data["identity"]["user"]).endswith("$"), path.name


def test_no_acceptance_script_targets_the_retired_records():
    scripts = (EVIDENCE.parents[2] / "tools" / "acceptance").glob("*.ps1")
    target = re.compile(
        r"\$(Out|dest|Pass1)\s*=.*data\\(m2-isolation-service|m15-service-acceptance)\.json"
    )
    for script in scripts:
        for n, line in enumerate(script.read_text(encoding="utf-8-sig").splitlines(), 1):
            assert not target.search(line), f"{script.name}:{n} writes a retired record"


def _strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, str):
        yield value


def test_machine_evidence_never_holds_a_machine_account_name():
    # LocalSystem's USERNAME is HOSTNAME$ (NetBIOS name, up to 15 characters). The first
    # pass-1 run on machine 262cc47030b1 leaked it through the E1 probe's "account".
    machine_account = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,14}\$$")
    for path in (EVIDENCE / "machines").rglob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        leaks = [s for s in _strings(data) if machine_account.match(s)]
        assert not leaks, f"{path}: machine account recorded: {leaks}"
