"""Service host: a clean agent stop must stay clean even if the Event Log is unavailable.

At the 2026-11-28 reboot of machine 262cc47030b1 the agent logged a clean stop
("agent stopped", 16 ms) but the SCM recorded event 7024 (service-specific error). pywin32
reports SERVICE_STOPPED with a non-zero code when SvcDoRun raises, and the only code after
the stop was the Application-log write. These tests pin that a failing event-log write no
longer escapes SvcDoRun. (Whether that was the actual cause is verified at the next reboot.)
"""

from __future__ import annotations

import logging
import sys
import threading

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="pywin32 service host")


class _FakeApp:
    def __init__(self, data_dir, stop, require_secure_data_dir):
        self.code = 0

    def run(self):
        return self.code

    def wake(self):
        pass


def _service(monkeypatch, tmp_path):
    from udcs_agent import service

    monkeypatch.setenv("UDCS_AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(service, "configure_logging", lambda *a, **k: None)
    monkeypatch.setattr(service, "AgentApp", _FakeApp)
    svc = service.UdcsAgentService.__new__(service.UdcsAgentService)  # no SCM registration
    svc._stop = threading.Event()
    svc._app = None
    return service, svc


def test_clean_stop_survives_an_unavailable_event_log(monkeypatch, tmp_path, caplog):
    import pywintypes

    service, svc = _service(monkeypatch, tmp_path)

    def unavailable(message):
        raise pywintypes.error(1722, "ReportEvent", "The RPC server is unavailable.")

    monkeypatch.setattr(service.servicemanager, "LogInfoMsg", unavailable)
    with caplog.at_level(logging.INFO, logger="udcs.agent"):
        svc.SvcDoRun()  # must not raise: that is what made pywin32 report a failure
    messages = [r.getMessage() for r in caplog.records]
    assert any("event log write failed" in m and "stopped (exit 0)" in m for m in messages)
    assert "service run returning" in messages


def test_event_log_is_written_when_available(monkeypatch, tmp_path):
    service, svc = _service(monkeypatch, tmp_path)
    written = []
    monkeypatch.setattr(service.servicemanager, "LogInfoMsg", written.append)
    svc.SvcDoRun()
    assert written[0].startswith("UDCSAgent starting (pid ")
    assert written[1] == "UDCSAgent stopped (exit 0)"
