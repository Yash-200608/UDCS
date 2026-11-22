"""Per-session helper: tells the service whether *this* session is in use.

Started at logon (HKLM Run key) with pythonw.exe, so it has no window, no tray
icon and no console. It reads only:
  - seconds since the last keyboard/mouse input in this session (GetLastInputInfo)
  - SHQueryUserNotificationState (full-screen app / presentation mode / busy)
and sends them every 2 s to the agent over a local named pipe. It never reads
window titles, process names or keystrokes, and has no network access.
"""

from __future__ import annotations

import ctypes
import json
import sys
import time

REPORT_INTERVAL_SECONDS = 2.0
_MUTEX_NAME = "Local\\UDCSSessionHelper"


def notification_state() -> int:
    state = ctypes.c_int(0)
    if ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(state)) != 0:
        return 0
    return state.value


def server_session(pipe: object) -> int | None:
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32")
    session = wintypes.ULONG()
    if kernel32.GetNamedPipeServerSessionId(wintypes.HANDLE(int(pipe)), ctypes.byref(session)):
        return int(session.value)
    return None


def main(require_service_server: bool = True) -> int:
    if sys.platform != "win32":
        return 2
    import pywintypes
    import win32api
    import win32event
    import win32file
    import winerror

    from udcs_agent.governor.helper_channel import CLIENT_ACCESS, CLIENT_SQOS, PIPE_NAME
    from udcs_agent.monitoring.idle import user_idle_seconds

    mutex = win32event.CreateMutex(None, False, _MUTEX_NAME)
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        return 0  # one helper per session
    pipe = None
    try:
        while True:
            if pipe is None:
                try:
                    pipe = win32file.CreateFile(
                        PIPE_NAME,
                        CLIENT_ACCESS,
                        0,
                        None,
                        win32file.OPEN_EXISTING,
                        CLIENT_SQOS,
                        None,
                    )
                except pywintypes.error:
                    time.sleep(10)  # agent not running (yet)
                    continue
                if require_service_server and server_session(pipe) != 0:
                    win32file.CloseHandle(pipe)  # not the UDCS service: say nothing
                    pipe = None
                    time.sleep(10)
                    continue
            idle = user_idle_seconds()
            message = json.dumps(
                {
                    "idle_seconds": 0.0 if idle is None else round(idle, 1),
                    "notification_state": notification_state(),
                }
            ).encode()
            try:
                win32file.WriteFile(pipe, message)
            except pywintypes.error:
                win32file.CloseHandle(pipe)
                pipe = None
                continue
            time.sleep(REPORT_INTERVAL_SECONDS)
    finally:
        if pipe is not None:
            win32file.CloseHandle(pipe)
        win32api.CloseHandle(mutex)


if __name__ == "__main__":
    sys.exit(main())
