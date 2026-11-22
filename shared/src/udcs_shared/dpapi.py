"""Windows DPAPI via ctypes (no pywin32 dependency).

Two scopes:
- "machine" (the node agent's credential): any process on *this* machine can
  decrypt, but a copied file is useless elsewhere. File ACLs restrict which accounts
  can read the file.
- "user" (a researcher's session token): only the same Windows user on this machine
  can decrypt. It protects against other accounts, not against malware running as
  that user.

Callers supply their own entropy, so a blob made for one purpose is not accepted
for another.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

_CRYPTPROTECT_UI_FORBIDDEN = 0x1
_CRYPTPROTECT_LOCAL_MACHINE = 0x4


class DpapiError(OSError):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _libs() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:
    if sys.platform != "win32":
        raise DpapiError("DPAPI is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for name in ("CryptProtectData", "CryptUnprotectData"):
        fn = getattr(crypt32, name)
        fn.argtypes = [
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR if name == "CryptProtectData" else ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        fn.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def _take(kernel32: ctypes.WinDLL, blob: _DataBlob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))


def _flags(scope: str) -> int:
    if scope == "machine":
        return _CRYPTPROTECT_UI_FORBIDDEN | _CRYPTPROTECT_LOCAL_MACHINE
    if scope == "user":
        return _CRYPTPROTECT_UI_FORBIDDEN
    raise ValueError(f"unknown DPAPI scope {scope!r}")


def protect(data: bytes, *, entropy: bytes, scope: str, description: str = "UDCS") -> bytes:
    flags = _flags(scope)
    crypt32, kernel32 = _libs()
    data_in, _keep1 = _blob(data)
    entropy_blob, _keep2 = _blob(entropy)
    out = _DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(data_in),
        description,
        ctypes.byref(entropy_blob),
        None,
        None,
        flags,
        ctypes.byref(out),
    ):
        raise DpapiError(ctypes.get_last_error(), "CryptProtectData failed")
    return _take(kernel32, out)


def unprotect(data: bytes, *, entropy: bytes) -> bytes:
    crypt32, kernel32 = _libs()
    data_in, _keep1 = _blob(data)
    entropy_blob, _keep2 = _blob(entropy)
    out = _DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(data_in),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out),
    ):
        raise DpapiError(ctypes.get_last_error(), "CryptUnprotectData failed")
    return _take(kernel32, out)
