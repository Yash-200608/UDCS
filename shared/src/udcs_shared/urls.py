"""Server URL rules shared by the node agent and the researcher client."""

from __future__ import annotations

from urllib.parse import urlsplit


def url_problem(url: str, *, allow_insecure_http: bool = False) -> str | None:
    """None if `url` is an acceptable controller URL, otherwise why not."""
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        return f"controller URL must be https:// (got {url!r})"
    if parts.scheme == "http" and not allow_insecure_http:
        return (
            "refusing plaintext http:// controller URL; use https:// "
            "(or allow_insecure_http for local development only)"
        )
    if not parts.hostname:
        return "controller URL has no host"
    if parts.username or parts.password or parts.query or parts.fragment:
        return "controller URL must not contain credentials, query or fragment"
    return None


def origin(url: str) -> str:
    """scheme://host[:port], normalised (lower case, no trailing dot, no default port):
    what a token is bound to. `https://h:443` and `https://h` are the same origin."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    default = {"https": 443, "http": 80}.get(scheme)
    port = f":{parts.port}" if parts.port and parts.port != default else ""
    return f"{scheme}://{host}{port}"
