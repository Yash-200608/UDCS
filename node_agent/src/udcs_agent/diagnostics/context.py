"""Who ran a diagnostic, on which machine and image, and whether it can count as
acceptance evidence.

Acceptance evidence comes only from the real context: the installed service
(LocalSystem, session 0) on the machine the gate is about. Everything else, such as an
interactive user, an elevated administrator, or a development PC, is a *diagnostic*:
useful, labelled, and never written where acceptance evidence lives
(docs/acceptance/data). The machine is identified by a hash of its name, not the name.
"""

from __future__ import annotations

import ctypes
import getpass
import hashlib
import os
import platform
import socket
import sys
from datetime import UTC, datetime

LOCAL_SYSTEM_SID = "S-1-5-18"


def _sid() -> str | None:
    if sys.platform != "win32":
        return None
    try:
        from udcs_agent.winplat import appcontainer as ac

        return ac.current_user_sid()
    except OSError:
        return None


def _elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _session_id() -> int | None:
    if sys.platform != "win32":
        return None
    session = ctypes.c_ulong()
    if ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        return int(session.value)
    return None


def execution_context() -> dict:
    sid = _sid()
    session = _session_id()
    if sid == LOCAL_SYSTEM_SID:
        context = "localsystem" if session == 0 else "localsystem-interactive-session"
    elif _elevated():
        context = "elevated-administrator"
    else:
        context = "interactive-user"
    return {
        "context": context,
        "is_local_system": sid == LOCAL_SYSTEM_SID,
        "elevated": _elevated(),
        "session_id": session,
        # LocalSystem's USERNAME is the machine account (HOSTNAME$): never record it.
        "user": "NT AUTHORITY\\SYSTEM" if sid == LOCAL_SYSTEM_SID else getpass.getuser(),
        "sid_kind": "LocalSystem" if sid == LOCAL_SYSTEM_SID else "user",
    }


def _edition() -> dict:
    if sys.platform != "win32":
        return {}
    import winreg

    out = {}
    try:
        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:
            for name in ("ProductName", "EditionID", "DisplayVersion", "UBR"):
                try:
                    out[name] = winreg.QueryValueEx(handle, name)[0]
                except OSError:
                    pass
    except OSError:
        pass
    return out


def machine_label() -> dict:
    from udcs_shared.exposure import image_key

    host = socket.gethostname()
    edition = _edition()
    return {
        "label": hashlib.sha256(host.lower().encode()).hexdigest()[:12],  # not the name itself
        "image": image_key(platform.release(), platform.version()),
        "build": sys.getwindowsversion().build if sys.platform == "win32" else None,
        "patch": edition.get("UBR"),
        "edition": edition.get("EditionID"),
        "product": edition.get("ProductName"),
        "display_version": edition.get("DisplayVersion"),
    }


def labelled(kind: str, payload: dict, *, evidence_context: bool = False) -> dict:
    """Wrap a diagnostic result. `evidence` is true only when the caller is on the real
    acceptance path AND this process is LocalSystem in session 0; it is never true for
    anything run interactively, elevated or not."""
    identity = execution_context()
    evidence = bool(evidence_context and identity["context"] == "localsystem")
    return {
        "kind": kind,
        "evidence": evidence,
        "note": None
        if evidence
        else "DIAGNOSTIC ONLY: not acceptance evidence (not the LocalSystem service path)",
        "generated_at": datetime.now(UTC).isoformat(),
        "machine": machine_label(),
        "identity": identity,
        "result": payload,
    }
