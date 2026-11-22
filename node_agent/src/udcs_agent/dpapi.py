"""The node credential's DPAPI protection: machine scope, node-specific entropy.

The implementation is shared (`udcs_shared.dpapi`); the researcher client uses the
same code with *user* scope and its own entropy.
"""

from __future__ import annotations

from udcs_shared import dpapi as _dpapi
from udcs_shared.dpapi import DpapiError

__all__ = ["DpapiError", "protect", "unprotect"]

_ENTROPY = b"udcs-node-credential-v1"


def protect(data: bytes) -> bytes:
    return _dpapi.protect(
        data, entropy=_ENTROPY, scope="machine", description="UDCS node credential"
    )


def unprotect(data: bytes) -> bytes:
    return _dpapi.unprotect(data, entropy=_ENTROPY)
