"""Interactive idle time: seconds since the last keyboard/mouse input.

This is groundwork for student-first protection (M4). It only measures input
in the *same Windows session* as the agent process. A service runs in session
0, where no user ever types, so we return None there instead of a misleading
"idle forever" — real detection from a service needs a per-session helper.
"""

from __future__ import annotations

import ctypes
import logging
import sys

logger = logging.getLogger(__name__)


def user_idle_seconds() -> float | None:
    if sys.platform != "win32":
        return None
    try:
        return _windows_idle_seconds()
    except OSError:
        logger.debug("idle time unavailable", exc_info=True)
        return None


def _windows_idle_seconds() -> float | None:
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)

    session_id = wintypes.DWORD()
    if not kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(session_id)):
        raise ctypes.WinError(ctypes.get_last_error())
    if session_id.value == 0:
        return None

    class LastInputInfo(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

    info = LastInputInfo(cbSize=ctypes.sizeof(LastInputInfo))
    if not user32.GetLastInputInfo(ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    kernel32.GetTickCount.restype = wintypes.DWORD
    elapsed_ms = (kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF  # handles 49.7-day wrap
    return elapsed_ms / 1000.0
