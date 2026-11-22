"""Build a self-contained node-agent folder for installation under Program Files.

    uv run python tools/package_agent.py STAGING_DIR

Layout produced:
    python/          private copy of the CPython runtime (no venv redirector, no user site)
    site/            only udcs-agent and its runtime dependencies (resolved from metadata)
    run_service.py   SCM entry point   ->  python\\python.exe -I run_service.py
    run_helper.py    per-session helper -> python\\pythonw.exe -I run_helper.py
    run_agent.py     admin CLI          ->  python\\python.exe -I run_agent.py <command>

Why a private interpreter: a LocalSystem service must not execute a python.exe that a
normal user can replace (the per-user Python install lives under the user's profile).
Installed under Program Files, every file is admin-writable only.
"""

from __future__ import annotations

import importlib.metadata as md
import shutil
import sys
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PACKAGES = {
    "udcs_agent": ROOT / "node_agent" / "src" / "udcs_agent",
    "udcs_shared": ROOT / "shared" / "src" / "udcs_shared",
}
_SKIP_RUNTIME = {
    "Lib/site-packages",
    "Lib/test",
    "Lib/idlelib",
    "Lib/tkinter",
    "Lib/turtledemo",
    "Doc",
    "Tools",
    "tcl",
    "include",
    "libs",
    "Scripts",
}

ENTRY = {
    "run_service.py": "from udcs_agent.service import main\nmain()\n",
    "run_helper.py": "import sys\nfrom udcs_agent.session_helper import main\nsys.exit(main())\n",
    "run_agent.py": "import sys\nfrom udcs_agent.cli import main\nsys.exit(main())\n",
}
_PRELUDE = (
    "import os, site, sys\n"
    "ROOT = os.path.dirname(os.path.abspath(__file__))\n"
    "site.addsitedir(os.path.join(ROOT, 'site'))  # also runs pywin32.pth (DLL search path)\n"
)


def runtime_closure(root: str = "udcs-agent") -> set[str]:
    env = default_environment()
    seen: set[str] = set()
    todo = [root]
    while todo:
        name = todo.pop()
        key = name.lower().replace("_", "-")
        if key in seen:
            continue
        seen.add(key)
        for spec in md.distribution(name).requires or []:
            req = Requirement(spec)
            if req.marker is None or req.marker.evaluate({**env, "extra": ""}):
                todo.append(req.name)
    return seen


def copy_distribution(name: str, site: Path) -> None:
    dist = md.distribution(name)
    for file in dist.files or []:
        rel = str(file).replace("\\", "/")
        if rel.startswith("..") or rel.endswith(".pyc") or "__editable__" in rel:
            continue
        source = Path(dist.locate_file(file))
        if source.is_file():
            target = site / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    staging = Path(argv[0]).resolve()
    if staging.exists() and any(staging.iterdir()):
        print(f"{staging} is not empty; choose a new directory")
        return 2
    runtime = Path(sys.base_prefix)
    shutil.copytree(
        runtime,
        staging / "python",
        ignore=lambda d, names: [
            n
            for n in names
            if Path(d, n).relative_to(runtime).as_posix() in _SKIP_RUNTIME or n == "__pycache__"
        ],
    )
    site = staging / "site"
    site.mkdir()
    closure = runtime_closure()
    for name in sorted(closure):
        if not name.startswith("udcs"):  # our own packages come from source, not editables
            copy_distribution(name, site)
    for package, source in SOURCE_PACKAGES.items():
        shutil.copytree(source, site / package, ignore=shutil.ignore_patterns("__pycache__"))
    for filename, body in ENTRY.items():
        (staging / filename).write_text(_PRELUDE + body, encoding="utf-8")
    size = sum(f.stat().st_size for f in staging.rglob("*") if f.is_file()) / 2**20
    print(f"staged {staging} ({size:.0f} MiB); dependencies: {', '.join(sorted(closure))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
