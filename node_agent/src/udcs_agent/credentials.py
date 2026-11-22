"""Persistent node credential storage."""

from __future__ import annotations

import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from udcs_agent import dpapi

_MAGIC_DPAPI = b"UDCSD1\n"
_MAGIC_PLAIN = b"UDCSP1\n"


class CredentialStoreError(Exception):
    pass


@dataclass(frozen=True)
class NodeCredential:
    node_id: uuid.UUID
    secret: str = field(repr=False)


class CredentialStore:
    def __init__(self, path: Path, *, use_dpapi: bool | None = None) -> None:
        self.path = path
        self._use_dpapi = sys.platform == "win32" if use_dpapi is None else use_dpapi

    def exists(self) -> bool:
        return self.path.exists()

    def save(self, credential: NodeCredential) -> None:
        payload = json.dumps({"node_id": str(credential.node_id), "secret": credential.secret})
        raw = payload.encode()
        data = _MAGIC_DPAPI + dpapi.protect(raw) if self._use_dpapi else _MAGIC_PLAIN + raw
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, self.path)

    def load(self) -> NodeCredential | None:
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            if data.startswith(_MAGIC_DPAPI):
                raw = dpapi.unprotect(data[len(_MAGIC_DPAPI) :])
            elif data.startswith(_MAGIC_PLAIN):
                raw = data[len(_MAGIC_PLAIN) :]
            else:
                raise CredentialStoreError(f"{self.path}: unrecognised credential file format")
            parsed = json.loads(raw)
            return NodeCredential(node_id=uuid.UUID(parsed["node_id"]), secret=parsed["secret"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise CredentialStoreError(f"{self.path}: cannot read credential ({exc})") from exc

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)
