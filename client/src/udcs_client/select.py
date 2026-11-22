"""Choosing which files of a project are packaged.

The control is an **allowlist**: only files matching `files.include` are packaged.
On top of it:
- a hard deny list (version control, caches, virtual environments, results, and
  well-known secret files) is never packaged, whatever the patterns say; naming such
  a file explicitly is an error, not a silent drop;
- links, junctions and special files are refused, never followed;
- a small content heuristic flags likely secrets in selected files. It is a
  heuristic, not a guarantee: the allowlist is the real control.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from udcs_client.spec import SPEC_FILENAME
from udcs_shared.transfer import is_reparse

MAX_WALK_ENTRIES = 200_000
HEURISTIC_MAX_BYTES = 1 << 20

DENY_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".ipynb_checkpoints",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "node_modules",
    "udcs-results",
    ".ssh",
    ".aws",
    ".azure",
    ".kube",
    ".gnupg",
    ".docker",
    ".idea",
    ".vscode",
    ".gcloud",
    "gcloud",  # ~/.config/gcloud: application default credentials
    ".terraform",
}
DENY_FILES = [
    "*.pyc",
    "*.pyo",
    ".env",
    ".env.*",
    "*.env",
    ".netrc",
    "_netrc",
    ".pypirc",
    ".git-credentials",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "*.keystore",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "*credentials*.json",
    "*service-account*.json",
    "application_default_credentials.json",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.*",
    ".pgpass",
    ".htpasswd",
    ".my.cnf",
    "*.ppk",
    "*.jks",
    "*.tfstate",
    "*.tfstate.*",
    "secrets.toml",
    "secrets.y*ml",
    "*.kubeconfig",
    "*.udcs-partial",
    SPEC_FILENAME,  # project metadata, not code
]
SECRET_PATTERNS = [
    ("private key", re.compile(rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("AWS access key id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(rb"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("Slack token", re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("password assignment", re.compile(rb"(?i)password\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']")),
]


@dataclass
class Selection:
    files: list[tuple[str, Path]] = field(default_factory=list)
    excluded: Counter = field(default_factory=Counter)  # reason -> count
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    flagged: list[str] = field(default_factory=list)


def _glob_regex(pattern: str) -> re.Pattern[str]:
    """POSIX glob with `**` (any number of directories, including none), `*` (within a
    segment) and `?`. Matched case-insensitively: Windows paths are."""
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:[^/]+/)*"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z", re.IGNORECASE)


def _has_wildcard(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def _denied_file(name: str) -> bool:
    lowered = name.casefold()
    return any(fnmatch.fnmatchcase(lowered, p.casefold()) for p in DENY_FILES)


def _is_venv(directory: Path) -> bool:
    return (directory / "pyvenv.cfg").is_file()


def scan_secrets(path: Path) -> list[str]:
    try:
        if path.stat().st_size > HEURISTIC_MAX_BYTES:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    return [label for label, pattern in SECRET_PATTERNS if pattern.search(data)]


def _reachable(directory: str, pattern: str) -> bool:
    """Could `pattern` match anything inside `directory`? Directories no pattern can
    reach are not walked at all, so a large data tree beside the code costs nothing."""
    psegs, dsegs = pattern.split("/"), directory.split("/")
    for i, segment in enumerate(dsegs):
        if i >= len(psegs) - 1:  # the pattern's last segment names files, not directories
            return psegs[i] == "**" if i < len(psegs) else False
        if psegs[i] == "**":
            return True
        if not fnmatch.fnmatchcase(segment.casefold(), psegs[i].casefold()):
            return False
    return True


def select_files(root: Path, include: list[str], allow_flagged: list[str]) -> Selection:
    selection = Selection()
    patterns = [(p, _glob_regex(p)) for p in include]
    explicit = {p.casefold() for p in include if not _has_wildcard(p)}
    allowed = {p.casefold() for p in allow_flagged}
    matched_patterns: set[str] = set()
    seen = 0
    for current, dirs, names in os.walk(root, followlinks=False):
        here = Path(current)
        keep = []
        for d in sorted(dirs):
            seen += 1
            path = here / d
            relative = path.relative_to(root).as_posix()
            folded = relative.casefold()
            denied = d.casefold() in DENY_DIRS
            if denied or (not is_reparse(path) and _is_venv(path)):
                selection.excluded[f"{d}/" if denied else "virtual environment"] += 1
                for e in sorted(explicit):
                    if e == folded or e.startswith(folded + "/"):
                        selection.problems.append(
                            f"{e} is never packaged: {relative}/ is "
                            + ("on the deny list" if denied else "a virtual environment")
                        )
            elif not any(_reachable(relative, p) for p in include):
                continue  # no include pattern can match inside: not walked
            elif is_reparse(path):
                selection.problems.append(
                    f"{relative}: a link or junction; links are never followed. Replace it "
                    "with a real directory, or move it out of the project"
                )
            else:
                keep.append(d)
        dirs[:] = keep
        for n in sorted(names):
            seen += 1
            if seen > MAX_WALK_ENTRIES:
                selection.problems.append(f"more than {MAX_WALK_ENTRIES} entries in the project")
                return selection
            path = here / n
            relative = path.relative_to(root).as_posix()
            hits = [p for p, regex in patterns if regex.match(relative)]
            if not hits:
                continue
            matched_patterns.update(hits)
            if _denied_file(n):
                if relative.casefold() in explicit:
                    selection.problems.append(
                        f"{relative} is never packaged (likely a secret or cache file); "
                        "remove it from files.include"
                    )
                else:
                    selection.excluded["secret or cache file"] += 1
                continue
            if is_reparse(path) or not path.is_file():
                selection.problems.append(f"{relative}: a link or special file; not followed")
                continue
            found = scan_secrets(path)
            if found and relative.casefold() not in allowed:
                selection.flagged.append(f"{relative}: looks like it contains a {found[0]}")
                continue
            selection.files.append((relative, path))
    for pattern, _ in patterns:
        if pattern not in matched_patterns:
            selection.warnings.append(f"files.include pattern {pattern!r} matches no file")
    return selection
