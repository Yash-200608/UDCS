"""Exit codes, and making server-supplied text safe to print on a terminal."""

from __future__ import annotations

import re
from enum import IntEnum


class Exit(IntEnum):
    OK = 0
    USAGE = 1
    INVALID = 2  # the project or its spec is invalid
    DISABLED = 3  # user code execution is disabled on this deployment
    SERVER = 4  # server, network or authentication problem
    VERIFICATION = 5  # a hash, size or path check failed
    JOB_FAILED = 6  # `watch`: the job ended failed or cancelled


class ClientError(Exception):
    """`transient`: a network failure or a 5xx, which a long-running command (`watch`)
    may retry. Authentication, not-found and validation errors never are."""

    def __init__(self, message: str, code: Exit = Exit.SERVER, *, transient: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.transient = transient


# ANSI CSI and OSC sequences, then any remaining C0/C1 control character except \t and \n.
_ESCAPES = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x9b[0-?]*[ -/]*[@-~]"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
MAX_LINE = 4096


def sanitize(text: object, *, secrets: tuple[str, ...] = ()) -> str:
    """Anything the server (or a workload, through logs) sends is untrusted: strip
    terminal escape sequences and control characters, cap line length, and scrub any
    secret that might be echoed back."""
    # Order matters: strip first (so a secret split by control characters is rejoined
    # before redaction), redact second, and only then cut (so a cut cannot split a
    # secret into an unrecognisable prefix).
    value = _ESCAPES.sub("", str(text))
    value = _CONTROL.sub("", value)
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[redacted]")
    return "\n".join(line[:MAX_LINE] for line in value.split("\n"))


def clip(text: str, limit: int) -> str:
    """Cut an already-sanitised message for display."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"
