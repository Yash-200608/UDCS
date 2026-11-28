"""Every Python interpreter the agent starts must run with -B.

Host-side children run as the agent's identity (LocalSystem under the service). Without
-B they write stdlib and agent .pyc files into the interpreter and install folders,
which the D-5 experiment saw as 43 changed files in its integrity snapshot.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "udcs_agent"


def _interpreter_argvs() -> list[tuple[str, int, list[str]]]:
    """(file, line, string flags) for every list literal whose second element is "-I"."""
    found = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.List) or len(node.elts) < 2:
                continue
            second = node.elts[1]
            if isinstance(second, ast.Constant) and second.value == "-I":
                flags = [
                    e.value
                    for e in node.elts[1:]
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
                found.append((str(path.relative_to(SRC)), node.lineno, flags))
    return found


def test_the_scan_finds_the_known_launch_sites():
    files = {f for f, _, _ in _interpreter_argvs()}
    # Guard against the scan silently matching nothing after a refactor.
    assert {
        "diagnostics\\isolation.py",
        "workloads\\manager.py",
        "workloads\\isolation.py",
    } <= {f.replace("/", "\\") for f in files}


def test_every_interpreter_launch_disables_bytecode_writes():
    missing = [(f, line) for f, line, flags in _interpreter_argvs() if "-B" not in flags]
    assert not missing, f"interpreter launched without -B: {missing}"
