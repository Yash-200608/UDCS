"""Interactive session state, readable from a service in session 0.

Verified on Windows 11 22000: WTSSessionInfoEx gives the console session's lock
state, but LastInputTime is 0 for the physical console, so idle time needs the
per-session helper. Usernames are deliberately never read: the agent needs to
know *whether* someone is there, not *who*.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass

from udcs_agent.winplat.api import WinApiError, kernel32

wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)

WTSActive, WTSConnected, WTSDisconnected = 0, 1, 4
_WTSSessionInfoEx = 25
_WTS_SESSIONSTATE_LOCK, _WTS_SESSIONSTATE_UNLOCK = 0, 1


class _SessionInfo(ctypes.Structure):
    _fields_ = [
        ("SessionId", wintypes.DWORD),
        ("pWinStationName", wintypes.LPWSTR),
        ("State", ctypes.c_int),
    ]


class _InfoExLevel1(ctypes.Structure):
    _fields_ = [
        ("SessionId", wintypes.ULONG),
        ("SessionState", ctypes.c_int),
        ("SessionFlags", wintypes.LONG),
        ("WinStationName", wintypes.WCHAR * 33),
        ("UserName", wintypes.WCHAR * 21),
        ("DomainName", wintypes.WCHAR * 18),
        ("LogonTime", ctypes.c_longlong),
        ("ConnectTime", ctypes.c_longlong),
        ("DisconnectTime", ctypes.c_longlong),
        ("LastInputTime", ctypes.c_longlong),
        ("CurrentTime", ctypes.c_longlong),
        ("IncomingBytes", wintypes.DWORD),
        ("OutgoingBytes", wintypes.DWORD),
        ("IncomingFrames", wintypes.DWORD),
        ("OutgoingFrames", wintypes.DWORD),
        ("IncomingCompressedBytes", wintypes.DWORD),
        ("OutgoingCompressedBytes", wintypes.DWORD),
    ]


class _InfoEx(ctypes.Structure):
    _fields_ = [("Level", wintypes.DWORD), ("Data", _InfoExLevel1)]


wtsapi32.WTSEnumerateSessionsW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.DWORD),
]
wtsapi32.WTSQuerySessionInformationW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.DWORD),
]
wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
kernel32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD


@dataclass(frozen=True)
class Session:
    session_id: int
    is_console: bool
    state: int  # WTSActive / WTSConnected / WTSDisconnected ...
    locked: bool | None  # None = unknown (treated as unlocked, i.e. fail toward the student)

    @property
    def interactive(self) -> bool:
        """A user is (or can be) at this session: active console or active remote session."""
        return self.state == WTSActive and self.session_id != 0


def _lock_state(session_id: int) -> bool | None:
    buffer, size = ctypes.c_void_p(), wintypes.DWORD()
    if not wtsapi32.WTSQuerySessionInformationW(
        None, session_id, _WTSSessionInfoEx, ctypes.byref(buffer), ctypes.byref(size)
    ):
        return None
    try:
        flags = ctypes.cast(buffer, ctypes.POINTER(_InfoEx)).contents.Data.SessionFlags
    finally:
        wtsapi32.WTSFreeMemory(buffer)
    return {_WTS_SESSIONSTATE_LOCK: True, _WTS_SESSIONSTATE_UNLOCK: False}.get(flags)


def list_sessions() -> list[Session]:
    console = kernel32.WTSGetActiveConsoleSessionId()
    buffer, count = ctypes.c_void_p(), wintypes.DWORD()
    if not wtsapi32.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(buffer), ctypes.byref(count)):
        raise WinApiError("WTSEnumerateSessionsW")
    try:
        array = ctypes.cast(buffer, ctypes.POINTER(_SessionInfo))
        raw = [(array[i].SessionId, array[i].State) for i in range(count.value)]
    finally:
        wtsapi32.WTSFreeMemory(buffer)
    sessions = []
    for session_id, state in raw:
        if session_id == 0:
            continue  # the services session never has a user
        locked = _lock_state(session_id) if state == WTSActive else None
        sessions.append(Session(session_id, session_id == console, state, locked))
    return sessions
