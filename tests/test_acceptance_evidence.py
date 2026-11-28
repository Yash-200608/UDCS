"""Acceptance evidence folder must never hold diagnostic results."""

import json
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / "docs" / "acceptance" / "data"


def _files():
    return sorted(EVIDENCE.glob("*.json"))


def test_no_diagnostic_results_in_evidence_folder():
    for path in _files():
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            assert data.get("evidence") is not False, f"{path.name} is labelled diagnostic"
            assert data.get("kind") != "preflight", f"{path.name} is a preflight diagnostic"


def test_exposure_summaries_in_evidence_folder_are_localsystem():
    for path in EVIDENCE.glob("m3-exposure-audit-*.json"):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        assert data.get("evidence") is True, path.name
        assert data["identity"]["context"] == "localsystem", path.name
        # LocalSystem's USERNAME is HOSTNAME$: a trailing $ means the host name leaked.
        assert not str(data["identity"]["user"]).endswith("$"), path.name
