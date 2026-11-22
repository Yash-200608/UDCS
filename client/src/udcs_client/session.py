"""Where the client keeps its configuration and session token, and how it connects.

- config.json: the server URL and CA bundle path. No secrets.
- session: the bearer token, bound to the origin it was issued by. On Windows it is
  encrypted with DPAPI in *user* scope (only this Windows account on this machine can
  decrypt it). Elsewhere it is a 0600 file in a 0700 directory, and the client refuses
  to use it if anyone else can read it. Neither protects against malware running as
  the same user.
- UDCS_TOKEN overrides the stored token for automation; it is never written to disk,
  and it must be bound to a server with UDCS_SERVER (or UDCS_TOKEN_ORIGIN).

Only https:// servers are accepted, redirects are never followed, and the token is
sent only to the origin it is bound to.
"""

from __future__ import annotations

import json
import os
import ssl
import stat
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from udcs_client.output import ClientError, Exit
from udcs_shared.urls import origin, url_problem

API_PREFIX = "/api/v1"
_MAGIC_DPAPI = b"UDCS-SESSION-DPAPI1\n"
_MAGIC_PLAIN = b"UDCS-SESSION-PLAIN1\n"
_ENTROPY = b"udcs-researcher-session-v1"


def config_dir() -> Path:
    override = os.environ.get("UDCS_CONFIG_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "udcs"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "udcs"


def _private_dir() -> Path:
    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(directory, 0o700)
    return directory


def validate_server(url: str) -> str:
    problem = url_problem(url, allow_insecure_http=False)  # no http:// for researchers, ever
    if problem:
        raise ClientError(problem, Exit.USAGE)
    return url.rstrip("/")


@dataclass
class Config:
    server: str | None = None
    ca_bundle: str | None = None


def load_config() -> Config:
    path = config_dir() / "config.json"
    if not path.is_file():
        return Config()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Config(server=data.get("server"), ca_bundle=data.get("ca_bundle"))
    except (ValueError, OSError):
        raise ClientError(
            f"{path} is unreadable; delete it and run `udcs login`", Exit.USAGE
        ) from None


def save_config(config: Config) -> None:
    path = _private_dir() / "config.json"
    path.write_text(json.dumps(asdict(config), indent=1), encoding="utf-8")


@dataclass
class Session:
    origin: str
    token: str
    expires_at: str
    username: str

    def expires_in_seconds(self, now: datetime | None = None) -> float:
        now = now or datetime.now(UTC)
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return 0.0
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return (expiry - now).total_seconds()


def _session_path() -> Path:
    return config_dir() / "session"


def save_session(session: Session, *, use_dpapi: bool | None = None) -> None:
    use_dpapi = sys.platform == "win32" if use_dpapi is None else use_dpapi
    raw = json.dumps(asdict(session)).encode()
    if use_dpapi:
        from udcs_shared import dpapi

        data = _MAGIC_DPAPI + dpapi.protect(
            raw, entropy=_ENTROPY, scope="user", description="UDCS researcher session"
        )
    else:
        data = _MAGIC_PLAIN + raw
    directory = _private_dir()
    temporary = directory / "session.tmp"
    temporary.unlink(missing_ok=True)
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600
    )
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.replace(temporary, _session_path())


def load_session() -> Session | None:
    path = _session_path()
    if not path.is_file():
        return None
    if sys.platform != "win32":
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ClientError(
                f"{path} is readable by other users; refusing to use it. "
                "Delete it and log in again",
                Exit.USAGE,
            )
    data = path.read_bytes()
    try:
        if data.startswith(_MAGIC_DPAPI):
            from udcs_shared import dpapi

            raw = dpapi.unprotect(data[len(_MAGIC_DPAPI) :], entropy=_ENTROPY)
        elif data.startswith(_MAGIC_PLAIN):
            raw = data[len(_MAGIC_PLAIN) :]
        else:
            raise ValueError("unknown session format")
        return Session(**json.loads(raw))
    except (OSError, ValueError, TypeError):
        raise ClientError(
            "the stored session is unreadable; run `udcs login`", Exit.USAGE
        ) from None


def delete_session() -> None:
    _session_path().unlink(missing_ok=True)


def resolve_server(flag: str | None) -> str:
    server = flag or os.environ.get("UDCS_SERVER") or load_config().server
    if not server:
        raise ClientError("no server configured: run `udcs login --server https://...`", Exit.USAGE)
    return validate_server(server)


def resolve_ca_bundle(flag: str | None) -> str | None:
    return flag or os.environ.get("UDCS_CA_BUNDLE") or load_config().ca_bundle


def token_for(server: str) -> str | None:
    """The token for `server`: UDCS_TOKEN, or the stored one if it was issued by the same
    origin. A token is never sent to a server it was not issued by."""
    env = os.environ.get("UDCS_TOKEN")
    if env:
        bound = os.environ.get("UDCS_TOKEN_ORIGIN") or os.environ.get("UDCS_SERVER")
        if not bound:
            raise ClientError(
                "UDCS_TOKEN needs UDCS_SERVER (or UDCS_TOKEN_ORIGIN) naming the server that "
                "issued it, so it is never sent anywhere else",
                Exit.USAGE,
            )
        if origin(bound) != origin(server):
            raise ClientError(
                f"UDCS_TOKEN belongs to {origin(bound)}, not {origin(server)}", Exit.USAGE
            )
        return env
    session = load_session()
    if session is None:
        return None
    if session.origin != origin(server):
        raise ClientError(
            f"you are logged in to {session.origin}, not {origin(server)}: run `udcs login`",
            Exit.USAGE,
        )
    return session.token


def build_http(server: str, ca_bundle: str | None, token: str | None) -> httpx.Client:
    """The production client: TLS verified against the system store or `ca_bundle`."""
    try:
        context = (
            ssl.create_default_context(cafile=ca_bundle)
            if ca_bundle
            else ssl.create_default_context()
        )
    except (OSError, ssl.SSLError) as exc:
        raise ClientError(f"cannot load CA bundle {ca_bundle}: {exc}", Exit.USAGE) from None
    return bind(
        httpx.Client(
            base_url=server + API_PREFIX,
            verify=context,
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
        ),
        server,
        token,
    )


def bind(http: httpx.Client, server: str, token: str | None) -> httpx.Client:
    """Attach the token so that it is only ever sent to `server`'s origin."""
    bound = origin(server)
    http.follow_redirects = False

    def _authorise(request: httpx.Request) -> None:
        request.headers.pop("Authorization", None)
        if token and origin(str(request.url)) == bound:
            request.headers["Authorization"] = f"Bearer {token}"

    http.event_hooks["request"] = [*http.event_hooks.get("request", []), _authorise]
    return http
