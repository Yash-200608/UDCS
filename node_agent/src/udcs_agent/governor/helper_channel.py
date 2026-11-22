"""Named-pipe server receiving per-session helper reports (Windows only).

Security:
- DACL: SYSTEM, Administrators and the pipe's creator (OWNER RIGHTS: SYSTEM in the
  service) full access; INTERACTIVE users get only
  FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE (0x100082). Generic write
  is deliberately NOT granted: it includes FILE_CREATE_PIPE_INSTANCE, which would
  let any student create a rogue server instance of this pipe ("pipe squatting").
- The first instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE, so if another
  process already owns the name the agent refuses to serve (and says so).
- Remote clients are rejected. Each report is
attributed to the *client's* session id (GetNamedPipeClientSessionId), never to
a session id the client claims, so one session can't speak for another.
"""

from __future__ import annotations

import ctypes
import json
import logging
import threading
from ctypes import wintypes

import pywintypes
import win32file
import win32pipe
import win32security

from udcs_agent.governor.interactive import HelperReports

logger = logging.getLogger(__name__)

PIPE_NAME = r"\\.\pipe\UDCSAgentSession"
_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x100082;;;IU)"
CLIENT_ACCESS = 0x00000002 | 0x00000080 | 0x00100000  # WRITE_DATA|READ_ATTRIBUTES|SYNCHRONIZE
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
# Clients allow only *identification*, so a rogue server can't impersonate them.
CLIENT_SQOS = 0x00100000 | 0x00010000  # SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
_PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
_MAX_MESSAGE = 512

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.GetNamedPipeClientSessionId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
_kernel32.GetNamedPipeClientSessionId.restype = wintypes.BOOL


def _client_session(pipe: object) -> int | None:
    session = wintypes.ULONG()
    if _kernel32.GetNamedPipeClientSessionId(int(pipe), ctypes.byref(session)):
        return int(session.value)
    return None


class HelperChannel(threading.Thread):
    def __init__(self, reports: HelperReports, stop: threading.Event) -> None:
        super().__init__(name="udcs-helper-channel", daemon=True)
        self._reports = reports
        self._stop_event = stop
        self.squatted = False

    def _security(self) -> pywintypes.SECURITY_ATTRIBUTES:
        attributes = win32security.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = (
            win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                _SDDL, win32security.SDDL_REVISION_1
            )
        )
        return attributes

    def _create(self, security: object, first: bool) -> object:
        return win32pipe.CreateNamedPipe(
            PIPE_NAME,
            win32pipe.PIPE_ACCESS_INBOUND | (_FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0),
            win32pipe.PIPE_TYPE_MESSAGE
            | win32pipe.PIPE_READMODE_MESSAGE
            | win32pipe.PIPE_WAIT
            | _PIPE_REJECT_REMOTE_CLIENTS,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            0,
            4096,
            0,
            security,
        )

    def run(self) -> None:
        security = self._security()
        try:
            pipe = self._create(security, first=True)
        except pywintypes.error as exc:
            self._squatting(exc)
            return
        while not self._stop_event.is_set():
            try:
                win32pipe.ConnectNamedPipe(pipe, None)  # blocks; stop() wakes it
            except pywintypes.error as exc:
                if exc.winerror != 535:  # ERROR_PIPE_CONNECTED is a normal race
                    logger.warning("helper pipe error: %s", exc)
                    win32file.CloseHandle(pipe)
                    try:
                        pipe = self._create(security, first=False)
                    except pywintypes.error as again:
                        self._squatting(again)
                        return
                    continue
            if self._stop_event.is_set():
                win32file.CloseHandle(pipe)
                break
            connected = pipe
            try:  # create the next instance BEFORE serving, so the name is never free
                pipe = self._create(security, first=False)
            except pywintypes.error as exc:
                win32file.CloseHandle(connected)
                self._squatting(exc)
                return
            threading.Thread(
                target=self._serve, args=(connected,), daemon=True, name="udcs-helper-client"
            ).start()

    def _squatting(self, exc: pywintypes.error) -> None:
        if exc.winerror == 5:  # access denied: someone else owns the pipe name
            logger.critical(
                "another process owns %s; helper reports disabled "
                "(sessions will be treated as ACTIVE)",
                PIPE_NAME,
            )
            self.squatted = True
        else:
            logger.error("cannot create helper pipe: %s", exc)

    def _serve(self, pipe: object) -> None:
        session = _client_session(pipe)
        try:
            if session is None or session == 0:
                return  # only interactive sessions may report
            while not self._stop_event.is_set():
                hr, data = win32file.ReadFile(pipe, _MAX_MESSAGE)
                if hr != 0:  # ERROR_MORE_DATA: oversized message -> drop the client
                    return
                try:
                    message = json.loads(data)
                    self._reports.update(
                        session, float(message["idle_seconds"]), int(message["notification_state"])
                    )
                except (ValueError, KeyError, TypeError):
                    return
        except pywintypes.error:
            return  # client went away
        finally:
            try:
                win32pipe.DisconnectNamedPipe(pipe)
            except pywintypes.error:
                pass
            win32file.CloseHandle(pipe)

    def stop(self) -> None:
        self._stop_event.set()
        try:  # unblock ConnectNamedPipe with a throwaway connection
            handle = win32file.CreateFile(
                PIPE_NAME, CLIENT_ACCESS, 0, None, win32file.OPEN_EXISTING, 0, None
            )
            win32file.CloseHandle(handle)
        except pywintypes.error:
            pass
