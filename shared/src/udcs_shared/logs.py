"""Structured (JSON-lines) logging with a correlation id, used by both sides."""

from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
import sys
from datetime import UTC, datetime
from pathlib import Path

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "udcs_request_id", default=None
)

_STANDARD_ATTRS = frozenset(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line; any `extra=` fields are included verbatim."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(
    level: str = "INFO", *, json_output: bool = True, log_file: Path | None = None
) -> None:
    """Log to stderr, or to a size-bounded rotating file (services have no console)."""
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 2**20, backupCount=3, encoding="utf-8"
        )
    else:
        handler = logging.StreamHandler(sys.stderr)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
