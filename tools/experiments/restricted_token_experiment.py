"""Decision D-4, Option B feasibility experiment. DIAGNOSTIC ONLY, never evidence.

Question: if the AppContainer token is built from a restricted token in which the
agent's user SID (SYSTEM in production) and Administrators are deny-only, does the
normal half of the access check stop a workload from reading the signed-in student's
registry hive and profile, while Python, the work directories, process cleanup and
CUDA still work?

It drives the REAL launch path: AppContainerIsolation (grants, profile, job, private
desktop), launch_in_appcontainer (CreateRestrictedToken + CreateProcessAsUserW with
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES and the LPAC policy), run_audit (the exposure
probe) and run_selftest (the isolation self-test). Only two things are swapped per variant:
  - appcontainer._restricted_token: which SIDs are passed to CreateRestrictedToken's
    SidsToDisable (documented API; no ntdll);
  - appcontainer.current_user_sid: the SID the normal-half grants name (production
    grants SYSTEM, which is deny-only under Option B, so something else must be named).

Variants:
  V0  production today: Administrators deny-only (negative control: shows what is reachable)
  V1  Option B: + the user SID (SYSTEM) deny-only; grants name the service/task SID
  V2  Option B, minimal: every group deny-only except that grant SID

Usage (from a snapshot made by tools/experiments/restricted_token_experiment.ps1):
  python -I -B restricted_token_experiment.py --out result.json --work <dir>
"""

import os
import site
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if os.path.isdir(os.path.join(ROOT, "site")):  # inside a package_agent.py snapshot
    site.addsitedir(os.path.join(ROOT, "site"))

import argparse  # noqa: E402
import contextlib  # noqa: E402
import ctypes  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import traceback  # noqa: E402
import winreg  # noqa: E402
from ctypes import wintypes  # noqa: E402
from pathlib import Path  # noqa: E402

from udcs_agent.diagnostics import exposure_audit  # noqa: E402
from udcs_agent.diagnostics.context import labelled  # noqa: E402
from udcs_agent.diagnostics.isolation import run_selftest  # noqa: E402
from udcs_agent.winplat import appcontainer as ac  # noqa: E402
from udcs_agent.workloads.isolation import AppContainerIsolation  # noqa: E402
from udcs_shared.exposure import finding_violation, sensitive_registry  # noqa: E402

ADMINS = "S-1-5-32-544"
SYSTEM = "S-1-5-18"
_adv = ctypes.WinDLL("advapi32", use_last_error=True)
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_adv.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
_adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
_adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
_adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
_adv.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
_k32.GetCurrentProcess.restype = wintypes.HANDLE
_k32.LocalFree.argtypes = [ctypes.c_void_p]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]

_FLAGS = {
    0x1: "mandatory",
    0x2: "enabled_by_default",
    0x4: "enabled",
    0x8: "owner",
    0x10: "deny_only",
    0x20: "integrity",
    0x40: "integrity_enabled",
    0x20000000: "resource",
    0xC0000000: "logon_id",
}


class _SAA(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


def _info(token, cls: int):
    size = wintypes.DWORD()
    _adv.GetTokenInformation(token, cls, None, 0, ctypes.byref(size))
    if not size.value:
        raise OSError(ctypes.get_last_error(), f"GetTokenInformation({cls}) size")
    buf = ctypes.create_string_buffer(size.value)
    if not _adv.GetTokenInformation(token, cls, buf, size, ctypes.byref(size)):
        raise OSError(ctypes.get_last_error(), f"GetTokenInformation({cls})")
    return buf


def _sid(ptr) -> str:
    s = wintypes.LPWSTR()
    if not _adv.ConvertSidToStringSidW(ptr, ctypes.byref(s)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW")
    value = s.value
    _k32.LocalFree(s)
    return value


def _name(sid: str):
    import win32security as ws

    try:
        name, domain, _ = ws.LookupAccountSid(None, ws.ConvertStringSidToSid(sid))
        return f"{domain}\\{name}" if domain else name
    except Exception:  # noqa: BLE001 - unnamed SIDs (capabilities, logon SIDs) are normal
        return None


def _flags(attrs: int) -> list[str]:
    out = [n for bit, n in _FLAGS.items() if bit != 0xC0000000 and attrs & bit]
    if attrs & 0xC0000000 == 0xC0000000:
        out.append("logon_id")
    return out


def _groups(buf) -> list[dict]:
    count = wintypes.DWORD.from_buffer(buf).value
    arr = (_SAA * count).from_buffer(buf, ctypes.sizeof(ctypes.c_void_p))
    return [
        {"sid": (s := _sid(a.Sid)), "name": _name(s), "flags": _flags(a.Attributes)} for a in arr
    ]


def token_info(token) -> dict:
    import win32security as ws

    out: dict = {}
    user = _SAA.from_buffer(_info(token, 1))
    out["user"] = {"sid": (u := _sid(user.Sid)), "name": _name(u), "flags": _flags(user.Attributes)}
    out["owner"] = _sid(ctypes.c_void_p.from_buffer(_info(token, 4)).value)
    out["groups"] = _groups(_info(token, 2))
    raw = _info(token, 3).raw
    count = int.from_bytes(raw[:4], "little")
    privileges = []
    for i in range(count):
        off = 4 + i * 12
        luid = int.from_bytes(raw[off : off + 8], "little")
        attrs = int.from_bytes(raw[off + 8 : off + 12], "little")
        try:
            name = ws.LookupPrivilegeName(None, luid)
        except Exception:  # noqa: BLE001
            name = f"luid:{luid}"
        privileges.append({"name": name, "enabled": bool(attrs & 0x2)})
    out["privileges"] = privileges
    for key, cls in (("is_appcontainer", 29), ("is_restricted", 40), ("is_lpac", 46)):
        try:
            out[key] = bool(wintypes.DWORD.from_buffer(_info(token, cls)).value)
        except OSError as exc:
            out[key] = f"unavailable ({exc})"
    try:
        out["restricting_sids"] = _groups(_info(token, 11))
    except OSError as exc:
        out["restricting_sids"] = f"unavailable ({exc})"
    try:
        ptr = ctypes.c_void_p.from_buffer(_info(token, 31)).value
        out["appcontainer_sid"] = _sid(ptr) if ptr else None
    except OSError as exc:
        out["appcontainer_sid"] = f"unavailable ({exc})"
    try:
        out["capabilities"] = [c["sid"] for c in _groups(_info(token, 30))]
    except OSError as exc:
        out["capabilities"] = f"unavailable ({exc})"
    il = _SAA.from_buffer(_info(token, 25))
    n = _adv.GetSidSubAuthorityCount(il.Sid).contents.value
    out["integrity_rid"] = hex(_adv.GetSidSubAuthority(il.Sid, n - 1).contents.value)
    return out


def own_token() -> dict:
    h = wintypes.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), 0x0008, ctypes.byref(h)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken")
    try:
        return token_info(h)
    finally:
        _k32.CloseHandle(h)


def pick_grant_sid(token: dict) -> tuple[str | None, str]:
    """The SID Option B's grants must name: enabled, and unique to the agent."""
    for g in token["groups"]:
        if g["sid"].startswith("S-1-5-80-") and "enabled" in g["flags"]:
            return g["sid"], "service SID (NT SERVICE\\...): the production analogue"
    for g in token["groups"]:
        if g["sid"].startswith("S-1-5-87-") and "enabled" in g["flags"]:
            return g["sid"], "task SID (NT TASK\\..., ProcessTokenSidType=Unrestricted)"
    for g in token["groups"]:
        if "logon_id" in g["flags"] and "enabled" in g["flags"]:
            return g["sid"], "logon SID: NOT production-valid (shared by the whole logon session)"
    for g in token["groups"]:
        if g["sid"] == "S-1-5-11" and "enabled" in g["flags"]:
            # Only so the experiment can answer whether the child can start at all. Granting
            # Authenticated Users is NOT acceptable in production (every user would pass the
            # normal half); the agent would use its service SID (sc sidtype unrestricted).
            return g["sid"], (
                "Authenticated Users: EXPERIMENT-ONLY stand-in, NOT production-valid "
                "(no service/task SID in a SYSTEM scheduled-task token)"
            )
    return None, "no enabled agent-unique SID in this token"


# -- variants ------------------------------------------------------------------------------


def _owner_and_dacl_with(grant_sid: str):
    """Option B's version of appcontainer._fix_owner_and_default_dacl. With the user SID
    deny-only, its allow ACE no longer lets the child open its own process and thread
    objects (measured: 0xC0000142 STATUS_DLL_INIT_FAILED), and the package SID only counts
    in the AppContainer half. So the default DACL also names the enabled grant SID."""

    def fix(token, package_sid):
        import ntsecuritycon as con
        import win32security as ws

        user_sid, _attrs = ws.GetTokenInformation(token, ws.TokenUser)
        ws.SetTokenInformation(token, ws.TokenOwner, user_sid)
        dacl = ws.ACL()
        for sid in (
            user_sid,
            ws.ConvertStringSidToSid(SYSTEM),
            ws.ConvertStringSidToSid(package_sid),
            ws.ConvertStringSidToSid(grant_sid),
        ):
            dacl.AddAccessAllowedAce(ws.ACL_REVISION, con.GENERIC_ALL, sid)
        ws.SetTokenInformation(token, ws.TokenDefaultDacl, dacl)

    return fix


def restricted_factory(disable: list[str], grant_sid: str | None = None):
    """Same as appcontainer._restricted_token, with a different SidsToDisable list (and,
    for Option B, the grant SID in the default DACL)."""
    fix_owner = _owner_and_dacl_with(grant_sid) if grant_sid else ac._fix_owner_and_default_dacl

    def _restricted_token(package_sid=None):
        own = wintypes.HANDLE()
        ac.api.check(
            ac._advapi.OpenProcessToken(
                ac._kernel32.GetCurrentProcess(), ac.TOKEN_ALL_NEEDED, ctypes.byref(own)
            ),
            "OpenProcessToken",
        )
        sids = [ac._Sid(s) for s in disable]
        try:
            arr = (ac.SID_AND_ATTRIBUTES * len(sids))(
                *[ac.SID_AND_ATTRIBUTES(s.ptr, 0) for s in sids]
            )
            restricted = wintypes.HANDLE()
            ac.api.check(
                ac._advapi.CreateRestrictedToken(
                    own,
                    ac.DISABLE_MAX_PRIVILEGE,
                    len(sids),
                    arr,
                    0,
                    None,
                    0,
                    None,
                    ctypes.byref(restricted),
                ),
                "CreateRestrictedToken",
            )
            if package_sid is not None:
                try:
                    fix_owner(restricted.value, package_sid)
                except Exception:
                    ac.api.CloseHandle(restricted)
                    raise
            return restricted
        finally:
            for s in sids:
                s.close()
            ac.api.CloseHandle(own)

    return _restricted_token


def students() -> list[tuple[str, str | None]]:
    """Loaded real-user hives (the signed-in student) and their profile folders."""
    out = []
    i = 0
    with winreg.OpenKey(winreg.HKEY_USERS, "") as hku:
        while True:
            try:
                name = winreg.EnumKey(hku, i)
            except OSError:
                break
            i += 1
            if re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-\d+", name):
                profile = None
                with contextlib.suppress(OSError):
                    key = rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{name}"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                        profile = os.path.expandvars(winreg.QueryValueEx(k, "ProfileImagePath")[0])
                out.append((name, profile))
    return out


def explicit_targets(people) -> list[tuple[str, str]]:
    """(category, target) pairs whose reachability is compared across variants."""
    windows = os.environ.get("SystemRoot", r"C:\Windows")
    targets = [("filesystem", windows + r"\System32\config")]
    for sid, profile in people:
        targets += [
            ("registry", rf"HKU\{sid}"),
            ("registry", rf"HKU\{sid}\Software"),
            ("registry", rf"HKU\{sid}\Environment"),
            (
                "registry",
                rf"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            ),
            ("registry", rf"HKU\{sid}_Classes"),
            ("registry", rf"HKU\{sid}\Environment\TEMP"),
        ]
        if profile:
            for rel in (
                "",
                "Documents",
                "Desktop",
                r"AppData\Roaming\Microsoft\Credentials",
                r"AppData\Local\Microsoft\Credentials",
                r"AppData\Roaming\Microsoft\Protect",
            ):
                targets.append(("filesystem", str(Path(profile) / rel) if rel else profile))
    return targets


def extend_plan(people):
    original = exposure_audit.build_plan

    def build_plan(data_dir, scratch, profile_folder):
        plan = original(data_dir, scratch, profile_folder)
        for sid, profile in people:
            plan["reg_roots"] += [
                ["HKU", sid, 1],
                ["HKU", rf"{sid}\Environment", 0],
                ["HKU", rf"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", 0],
                ["HKU", f"{sid}_Classes", 1],
            ]
            plan["sensitive_values"] += [["HKU", rf"{sid}\Environment", "TEMP"]]
            if profile:
                for rel in (
                    "",
                    "Documents",
                    "Desktop",
                    r"AppData\Roaming\Microsoft\Credentials",
                    r"AppData\Local\Microsoft\Credentials",
                    r"AppData\Roaming\Microsoft\Protect",
                ):
                    plan["fs_roots"].append([str(Path(profile) / rel) if rel else profile, 1])
        return plan

    return original, build_plan


def reachable(findings, category, target) -> list[str]:
    t = target.lower().rstrip("\\")
    return sorted(
        {
            f.access
            for f in findings
            if f.category.value == category
            and (f.target.lower().rstrip("\\") == t or f.target.lower().startswith(t + "\\"))
        }
    )


def run_variant(label: str, disable: list[str], grant_sid: str, work: Path, people) -> dict:
    out: dict = {"disable": disable, "grant_sid": grant_sid}
    captured: dict = {}
    original_launch = AppContainerIsolation.launch

    def launch(self, *a, **k):
        process = original_launch(self, *a, **k)
        h = wintypes.HANDLE()
        if _adv.OpenProcessToken(process.handle, 0x0008, ctypes.byref(h)):
            try:
                captured.setdefault("tokens", []).append(token_info(h))
            except Exception as exc:  # noqa: BLE001
                captured.setdefault("token_errors", []).append(repr(exc))
            finally:
                _k32.CloseHandle(h)
        else:
            captured.setdefault("token_errors", []).append(
                f"OpenProcessToken {ctypes.get_last_error()}"
            )
        return process

    saved = (ac._restricted_token, ac.current_user_sid, exposure_audit.build_plan)
    production = label.startswith("V0")
    ac._restricted_token = restricted_factory(disable, None if production else grant_sid)
    ac.current_user_sid = lambda: grant_sid
    exposure_audit.build_plan = extend_plan(people)[1]
    AppContainerIsolation.launch = launch
    data = work / label
    try:
        try:
            report, _plan = exposure_audit.run_audit(data / "audit")
            findings = report.findings
            hard = [v for f in findings if (v := finding_violation(f))]
            counts: dict = {}
            for f in findings:
                key = f"{f.category.value}:{f.access}"
                counts[key] = counts.get(key, 0) + 1
            out["audit"] = {
                "probe_ran": bool(report.coverage),
                "errors": report.errors[:10],
                "truncated": report.truncated,
                "privileges": report.privileges,
                "integrity_rid": hex(report.integrity_rid),
                "appcontainer": report.appcontainer,
                "coverage": report.coverage,
                "reachable_counts": counts,
                "violation_count": len(hard),
                "violations_sample": hard[:25],
                "student_registry_findings": sum(
                    1
                    for f in findings
                    if f.category.value == "registry" and sensitive_registry(f.target)
                ),
                "explicit_targets": {
                    f"{c} {t}": reachable(findings, c, t) for c, t in explicit_targets(people)
                },
            }
        except Exception as exc:  # noqa: BLE001
            out["audit"] = {
                "error": f"{type(exc).__name__}: {exc}",
                "trace": traceback.format_exc()[-1500:],
            }
        try:
            iso = AppContainerIsolation(data / "selftest")
            st = run_selftest(data / "selftest" / "scratch", iso)
            out["selftest"] = {
                "passed": st.get("passed"),
                "failed_checks": [c["name"] for c in st.get("checks", []) if not c["pass"]],
                "passed_checks": [c["name"] for c in st.get("checks", []) if c["pass"]],
                "kill_tree": st.get("kill_tree"),
                "cuda_in_sandbox": st.get("cuda_in_sandbox"),
                "errors": st.get("errors"),
            }
        except Exception as exc:  # noqa: BLE001
            out["selftest"] = {
                "error": f"{type(exc).__name__}: {exc}",
                "trace": traceback.format_exc()[-1500:],
            }
        out["child_tokens"] = captured.get("tokens", [])[:1]  # all launches share the same shape
        out["child_token_count"] = len(captured.get("tokens", []))
        out["token_errors"] = captured.get("token_errors", [])
    finally:
        ac._restricted_token, ac.current_user_sid, exposure_audit.build_plan = saved
        AppContainerIsolation.launch = original_launch
        scope = (
            AppContainerIsolation(data / "audit").scope,
            AppContainerIsolation(data / "selftest").scope,
        )
        out["leftover_profiles"] = [p for s in scope for p in ac.list_profiles(f"udcs.{s}.")]
        shutil.rmtree(data, ignore_errors=True)
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args(argv)
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    own = own_token()
    grant_sid, grant_kind = pick_grant_sid(own)
    people = students()
    result: dict = {
        "experiment": "D-4 option B: restricted SYSTEM token + AppContainer",
        "apis": [
            "OpenProcessToken",
            "CreateRestrictedToken(DISABLE_MAX_PRIVILEGE, SidsToDisable)",
            "SetTokenInformation(TokenOwner, TokenDefaultDacl)",
            "InitializeProcThreadAttributeList / UpdateProcThreadAttribute("
            "SECURITY_CAPABILITIES, ALL_APPLICATION_PACKAGES_POLICY)",
            "CreateProcessAsUserW(EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED)",
            "AssignProcessToJobObject / TerminateJobObject (via JobObject)",
            "CreateAppContainerProfile / DeleteAppContainerProfile",
            "GetTokenInformation (child token inspection)",
        ],
        "parent_token": own,
        "grant_sid": grant_sid,
        "grant_sid_kind": grant_kind,
        "students": [s for s, _ in people],
        "variants": {},
    }
    capability = ac.capability_sid(ac.RUNTIME_CAPABILITY)
    ac.workload_desktop(capability)  # created once, as in the agent
    user_sid = own["user"]["sid"]
    groups = [g["sid"] for g in own["groups"] if "integrity" not in g["flags"]]
    variants = [("V0_production", [ADMINS], user_sid)]
    if grant_sid:
        # Option B also needs the window station / desktop to grant the new grant SID.
        state = ac._desktop_state
        for key, mask in (("winsta", ac._WINSTA_ALL), ("desktop", ac._DESKTOP_ALL)):
            handle = state.get(key)
            if handle and (key == "desktop" or state.get("private_station")):
                ac._grant_window_object(handle, grant_sid, mask)
        variants.append(("V1_optionB", [ADMINS, user_sid], grant_sid))
        variants.append(
            (
                "V2_optionB_minimal",
                sorted({user_sid, *[g for g in groups if g != grant_sid]}),
                grant_sid,
            )
        )
    for label, disable, gsid in variants:
        result["variants"][label] = run_variant(label, disable, gsid, work, people)
    wrapped = labelled("restricted-token-experiment", result, evidence_context=False)
    Path(args.out).write_text(json.dumps(wrapped, indent=1), encoding="utf-8")
    print(f"written {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
