"""Windows service host for the UDCS node agent (pywin32).

Installed by infrastructure/windows/install-agent.ps1 with:
  binPath    "<agent>\\python\\python.exe" -I "<agent>\\run_service.py"   (no venv redirector)
  start      delayed-auto (starts after boot without a logon)
  recovery   restart 5 s / 15 s / 60 s, failure flag on (non-crash failures count)
  account    LocalSystem (needed later to launch workloads under a low-privilege account)
The SCM launches the process with no arguments; that path hosts the service.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path

import servicemanager
import win32service
import win32serviceutil

from udcs_agent.app import EXIT_OK, AgentApp
from udcs_agent.config import default_data_dir
from udcs_shared.logs import configure_logging

SERVICE_NAME = "UDCSAgent"


class UdcsAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "UDCS Node Agent"
    _svc_description_ = (
        "Lends this computer's spare CPU/GPU capacity to the university's UDCS compute pool. "
        "The local user always has priority."
    )

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self._stop = threading.Event()
        self._app: AgentApp | None = None

    def GetAcceptedControls(self) -> int:
        return (
            super().GetAcceptedControls()
            | win32service.SERVICE_ACCEPT_SHUTDOWN
            | win32service.SERVICE_ACCEPT_SESSIONCHANGE
        )

    def SvcOtherEx(self, control: int, event_type: int, data: object) -> None:
        if control == win32service.SERVICE_CONTROL_SESSIONCHANGE and self._app is not None:
            self._app.wake()  # logon/logoff/lock/unlock: re-assess now, not in 1 s

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=10_000)
        self._stop.set()

    def SvcShutdown(self) -> None:
        self.SvcStop()

    def SvcDoRun(self) -> None:
        data_dir = Path(os.environ.get("UDCS_AGENT_DATA_DIR") or default_data_dir())
        configure_logging("INFO", json_output=True, log_file=data_dir / "logs" / "agent.log")
        servicemanager.LogInfoMsg(f"{SERVICE_NAME} starting (pid {os.getpid()})")
        self._app = AgentApp(data_dir, stop=self._stop, require_secure_data_dir=True)
        try:
            code = self._app.run()
        except Exception:
            logging.getLogger("udcs.agent").exception("agent crashed")
            code = 1
        servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped (exit {code})")
        if code != EXIT_OK:
            # Exiting without reporting SERVICE_STOPPED is treated by the SCM as a failure,
            # which triggers the configured recovery (restart).
            logging.shutdown()
            os._exit(code)


def main() -> None:
    if len(sys.argv) == 1:  # started by the SCM
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(UdcsAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:  # developer use: `python -m udcs_agent.service debug`
        win32serviceutil.HandleCommandLine(UdcsAgentService)


if __name__ == "__main__":
    main()
