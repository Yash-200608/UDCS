"""DPAPI scopes: the node credential stays machine-scoped; researcher sessions are
user-scoped, and blobs made for one purpose do not open with another's entropy."""

from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI")


def test_user_and_machine_scope_round_trip():
    from udcs_shared import dpapi

    for scope in ("user", "machine"):
        blob = dpapi.protect(b"secret", entropy=b"e1", scope=scope)
        assert b"secret" not in blob
        assert dpapi.unprotect(blob, entropy=b"e1") == b"secret"


def test_entropy_separates_purposes():
    from udcs_shared import dpapi

    blob = dpapi.protect(b"secret", entropy=b"researcher", scope="user")
    with pytest.raises(dpapi.DpapiError):
        dpapi.unprotect(blob, entropy=b"node")


def test_unknown_scope_is_refused():
    from udcs_shared import dpapi

    with pytest.raises(ValueError):
        dpapi.protect(b"x", entropy=b"e", scope="everyone")


def test_agent_wrapper_keeps_machine_scope_and_its_entropy():
    from udcs_agent import dpapi as agent_dpapi
    from udcs_shared import dpapi

    blob = agent_dpapi.protect(b"node-credential")
    assert agent_dpapi.unprotect(blob) == b"node-credential"
    assert dpapi.unprotect(blob, entropy=b"udcs-node-credential-v1") == b"node-credential"
