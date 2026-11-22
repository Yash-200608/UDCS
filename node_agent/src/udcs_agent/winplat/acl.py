"""Verify the agent's data directory is controlled only by SYSTEM / Administrators.

A LocalSystem service writing into a directory that a student controls (owner,
write/WRITE_DAC ACE, or a planted junction) is a local privilege escalation. The
service refuses to lend resources if this check fails.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import ntsecuritycon as con
import win32security

_TRUSTED = {
    "S-1-5-18",  # SYSTEM
    "S-1-5-32-544",  # Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
}
_WRITE_MASK = (
    con.FILE_WRITE_DATA
    | con.FILE_APPEND_DATA
    | con.FILE_WRITE_EA
    | con.FILE_WRITE_ATTRIBUTES
    | con.FILE_DELETE_CHILD
    | con.DELETE
    | con.WRITE_DAC
    | con.WRITE_OWNER
    | con.GENERIC_WRITE
    | con.GENERIC_ALL
)


def _problem(path: Path) -> str | None:
    if os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return f"{path} is a reparse point (junction/symlink)"
    sd = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )
    owner = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
    if owner not in _TRUSTED:
        return f"{path} is owned by {owner}"
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        return f"{path} has a NULL DACL (everyone has full access)"
    for i in range(dacl.GetAceCount()):
        (ace_type, _flags), mask, sid = dacl.GetAce(i)[:3]
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE:
            continue
        sid_text = win32security.ConvertSidToStringSid(sid)
        if sid_text not in _TRUSTED and mask & _WRITE_MASK:
            return f"{path} grants write access to {sid_text}"
    return None


def insecure_reason(data_dir: Path) -> str | None:
    """None if the data dir, its parent and everything inside are admin-only."""
    for candidate in (data_dir.parent, data_dir):
        reason = _problem(candidate)
        if reason:
            return reason
    for root, dirs, files in os.walk(data_dir):
        for name in dirs + files:
            reason = _problem(Path(root) / name)
            if reason:
                return reason
    return None
