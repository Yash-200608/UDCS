"""Coarse interactive state from session state (service-visible) + helper reports.

Fail-safe rules (operating model §3, Rule 2):
- cannot read sessions          -> ACTIVE
- unlocked session, no report   -> ACTIVE  (helper missing, crashed or stale)
- IDLE only when *every* unlocked session's helper reports idle >= threshold.
A helper speaks only for its own session (the pipe server checks the client's
session id), so a student can't make UDCS more aggressive on someone else's
session. A student *can* claim to be idle on their own session; that only
affects their own machine and is still bounded by measured pressure (AWAY
requires low non-UDCS CPU).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from udcs_shared.protection import InteractiveState

# SHQueryUserNotificationState values that mean "hands off".
QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN, QUNS_PRESENTATION_MODE = 2, 3, 4
_PROTECTED_STATES = {QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN, QUNS_PRESENTATION_MODE}
REPORT_MAX_AGE_SECONDS = 10.0


@dataclass(frozen=True)
class HelperReport:
    received: float
    idle_seconds: float
    notification_state: int


class HelperReports:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.Lock()
        self._reports: dict[int, HelperReport] = {}
        self._clock = clock

    def update(self, session_id: int, idle_seconds: float, notification_state: int) -> None:
        if not (0 <= idle_seconds < 10 * 365 * 86400) or not (0 <= notification_state <= 16):
            return  # malformed: ignore (the session then counts as ACTIVE)
        with self._lock:
            self._reports[session_id] = HelperReport(
                self._clock(), idle_seconds, notification_state
            )

    def get(self, session_id: int) -> HelperReport | None:
        with self._lock:
            report = self._reports.get(session_id)
        if report is None or self._clock() - report.received > REPORT_MAX_AGE_SECONDS:
            return None
        return report


class InteractiveMonitor:
    def __init__(
        self,
        reports: HelperReports,
        *,
        idle_after_seconds: Callable[[], float],
        list_sessions: Callable[[], list] | None = None,
    ) -> None:
        self._reports = reports
        self._idle_after = idle_after_seconds
        if list_sessions is None:
            from udcs_agent.winplat import IS_WINDOWS

            if IS_WINDOWS:
                from udcs_agent.winplat.sessions import list_sessions as real

                list_sessions = real
        self._list_sessions = list_sessions
        self._was_locked: dict[int, bool] = {}
        self._unlocked_at: dict[int, float] = {}
        self._clock = reports._clock

    def __call__(self) -> tuple[InteractiveState, bool]:
        if self._list_sessions is None:
            return InteractiveState.ACTIVE, False
        try:
            sessions = self._list_sessions()
        except OSError:
            return InteractiveState.ACTIVE, False
        interactive = [s for s in sessions if s.interactive]
        if not interactive:
            return InteractiveState.NO_USER, False
        now = self._clock()
        for s in interactive:
            locked = s.locked is True
            if self._was_locked.get(s.session_id, True) and not locked:
                self._unlocked_at[s.session_id] = now  # logon or unlock: a fresh start
            self._was_locked[s.session_id] = locked
        unlocked = [s for s in interactive if s.locked is not True]
        if not unlocked:
            return InteractiveState.LOCKED, False
        protected, all_idle = False, True
        idle_after = self._idle_after()
        for session in unlocked:
            report = self._reports.get(session.session_id)
            if report is not None and report.received < self._unlocked_at.get(
                session.session_id, float("-inf")
            ):
                report = None  # measured before the student came back: stale
            if report is None:
                all_idle = False
                continue
            if report.notification_state in _PROTECTED_STATES:
                protected = True
            if report.idle_seconds < idle_after:
                all_idle = False
        return (InteractiveState.IDLE if all_idle else InteractiveState.ACTIVE), protected
