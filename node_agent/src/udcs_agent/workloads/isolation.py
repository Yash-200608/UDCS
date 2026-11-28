"""Isolation adapter: how a workload process is created.

Levels:
- `host`: the process runs in a Job Object only, with the agent's own identity. Used
  for the four built-in catalog workloads where no stronger isolation is available
  on a node. They are UDCS's own code, never user code.
- `appcontainer`: the process runs in its own AppContainer (a per-workload package
  SID), from a restricted token with no privileges, inside the same Job Object
  (governor limits, kill-on-close, UI restrictions). See winplat/appcontainer.py.

Rules:
- A workload that requires `appcontainer` is never started any other way. If the
  backend is missing or fails, the workload fails, and the reason is recorded.
- Per-workload grants: modify on its own workdir, read/execute on approved inputs.
  The runtime (interpreter and catalog files) is granted to a shared capability.
  Nothing else is granted.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import sys
from enum import StrEnum
from pathlib import Path

logger = logging.getLogger(__name__)

RUNTIME_FILES = ("synthetic.py", "cudadrv.py")
_DIAGNOSTIC_FILES = ("isolation_probe.py", "exposure_probe.py")


class IsolationLevel(StrEnum):
    HOST = "host"
    APPCONTAINER = "appcontainer"


class IsolationUnavailable(RuntimeError):
    """The required isolation cannot be provided; the workload must not start."""


def profile_name(scope: str, workload_id: str) -> str:
    """`udcs.<agent scope>.<hash of the workload id>`: at most 34 characters (Windows
    allows 64) for any valid workload id. It is scoped per agent, so one agent's orphan
    sweep never touches another agent's profiles under the same Windows account."""
    digest = hashlib.sha256(workload_id.encode("utf-8")).hexdigest()[:20]
    return f"udcs.{scope}.{digest}"


class AppContainerIsolation:
    level = IsolationLevel.APPCONTAINER

    def __init__(self, data_dir: Path, *, python: str | None = None) -> None:
        self.runtime = data_dir / "runtime"
        self.scope = hashlib.sha256(str(data_dir.resolve()).lower().encode()).hexdigest()[:8]
        self.python = python or getattr(sys, "_base_executable", sys.executable)
        self.python_home = Path(self.python).parent
        self._capability: str | None = None

    def profile_name(self, workload_id: str) -> str:
        return profile_name(self.scope, workload_id)

    # -- runtime ---------------------------------------------------------------------------

    def ensure_runtime(self) -> str:
        """Install the catalog runtime and its read-only grants; return the capability SID.
        Idempotent; the grant on the interpreter directory is made once per node."""
        from udcs_agent.winplat import appcontainer as ac

        try:
            # Checked on every launch, not just once: the runtime is what every isolated
            # workload executes, so a modified copy is repaired before it is ever run.
            self.runtime.mkdir(parents=True, exist_ok=True)
            here = Path(__file__).parent
            sources = [here / f for f in RUNTIME_FILES] + [
                here.parent / "diagnostics" / f for f in _DIAGNOSTIC_FILES
            ]
            for source in sources:
                target = self.runtime / source.name
                if not target.exists() or target.read_bytes() != source.read_bytes():
                    if target.exists():
                        logger.warning("isolated runtime file %s was modified; restoring", target)
                    tmp = target.with_suffix(".tmp")
                    shutil.copyfile(source, tmp)
                    tmp.replace(target)
            if self._capability is not None:
                return self._capability
            capability = ac.capability_sid(ac.RUNTIME_CAPABILITY)
            # An AppContainer access check needs BOTH the normal token check (the agent's
            # user, with Administrators deny-only) and the package/capability check. Name
            # the agent's own user too, so admin-only directories work (measured on CI: an
            # elevated-admin parent could not even write its workload's error file).
            user = ac.current_user_sid()
            ac.grant(self.runtime, capability, ac.READ_EXECUTE)
            ac.grant(self.runtime, user, ac.READ_EXECUTE)
            ac.grant(self.python_home, capability, ac.READ_EXECUTE)
            ac.grant(self.python_home, user, ac.READ_EXECUTE)
        except OSError as exc:
            raise IsolationUnavailable(f"cannot prepare the isolated runtime: {exc}") from exc
        self._capability = capability
        return capability

    @staticmethod
    def sandbox(package: str, capability: str):
        """LPAC (ignores everything Windows grants to ALL APPLICATION PACKAGES) plus the
        `registryRead` capability, without which Python dies at start (0xC0000022).
        Measured 2026-11-28: a standard AppContainer could open the signed-in user's
        per-user services (e.g. WpnUserService_*) for SERVICE_STOP through their
        ALL APPLICATION PACKAGES grant; under this sandbox even OpenSCManager is denied."""
        from udcs_agent.winplat import appcontainer as ac

        return ac.SandboxSpec(
            package, (capability, ac.capability_sid(ac.REGISTRY_READ_CAPABILITY)), lpac=True
        )

    def bootstrap(self, module: str) -> str:
        """A sandboxed process has no console, so a crash leaves its traceback in its own
        workdir (the current directory) as workload-error.txt."""
        return "\n".join(
            [
                "import sys, traceback",
                f"sys.path[:0] = [{str(self.runtime)!r}]",
                "try:",
                f"    from {module} import main",
                "    rc = main()",
                "except SystemExit:",
                "    raise",
                "except BaseException:",
                "    with open('workload-error.txt', 'w', encoding='utf-8') as f:",
                "        f.write(traceback.format_exc())",
                "    rc = 1",
                "sys.exit(rc)",
            ]
        )

    # -- per workload ----------------------------------------------------------------------

    def launch(
        self,
        workload_id: str,
        module: str,
        args: list[str],
        job,
        workdir: Path,
        *,
        read_only: tuple[Path, ...] = (),
    ):
        """Start `module.main(args)` in this workload's AppContainer, inside `job`."""
        from udcs_agent.winplat import appcontainer as ac

        capability = self.ensure_runtime()
        try:
            package = ac.ensure_profile(self.profile_name(workload_id))
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "tmp").mkdir(exist_ok=True)
            ac.grant(workdir, package, ac.MODIFY)
            ac.grant(workdir, ac.current_user_sid(), ac.MODIFY)  # the agent's own identity
            for path in read_only:
                ac.grant(path, package, ac.READ_EXECUTE)
                ac.grant(path, ac.current_user_sid(), ac.READ_EXECUTE)
            ac.set_ui_restrictions(job)
            env = {
                "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
                "TEMP": str(workdir / "tmp"),
                "TMP": str(workdir / "tmp"),
            }
            argv = [self.python, "-I", "-S", "-B", "-c", self.bootstrap(module), *args]
            return ac.launch_in_appcontainer(
                argv,
                job,
                self.sandbox(package, capability),
                cwd=workdir,
                env=env,
                desktop=ac.workload_desktop(capability),
            )
        except OSError as exc:
            raise IsolationUnavailable(f"AppContainer launch failed: {exc}") from exc

    def package_bootstrap(self, root: Path, entry: Path, args: list[str], paths: list[Path]) -> str:
        """Run a researcher's entry script as __main__ with an explicit import path (the
        package source and its approved environment only; -I -S already removed every
        environment- and site-based path). stdout/stderr go to logs/, the only place the
        agent reads them from; the process has no console and inherits no handles."""
        return "\n".join(
            [
                "import runpy, sys",
                "sys.stdout = open('logs/stdout.txt', 'a', encoding='utf-8', buffering=1)",
                "sys.stderr = open('logs/stderr.txt', 'a', encoding='utf-8', buffering=1)",
                f"sys.path[:0] = {[str(p) for p in paths]!r}",
                f"sys.argv = [{str(entry)!r}, *{list(args)!r}]",
                f"runpy.run_path({str(entry)!r}, run_name='__main__')",
            ]
        )

    def launch_package(
        self,
        workload_id: str,
        job,
        root: Path,
        *,
        entry: Path,
        args: list[str],
        import_paths: list[Path],
        read_only: tuple[Path, ...],
        writable: tuple[Path, ...],
    ):
        """Start a staged package in this workload's AppContainer, inside `job`.

        Grants, all to this workload's own package SID (and the agent's user, which an
        AppContainer access check also needs): read/execute on the staging root and the
        read-only parts (source, environment, inputs, config), modify on `writable`
        only (out/, state/, logs/, tmp/). The interpreter comes from the shared runtime
        capability. No network capability is ever added."""
        from udcs_agent.winplat import appcontainer as ac

        capability = self.ensure_runtime()
        try:
            package = ac.ensure_profile(self.profile_name(workload_id))
            user = ac.current_user_sid()
            ac.grant(root, package, ac.READ_EXECUTE)
            ac.grant(root, user, ac.READ_EXECUTE)
            for path in read_only:
                ac.grant(path, package, ac.READ_EXECUTE)
                ac.grant(path, user, ac.READ_EXECUTE)
            for path in writable:
                path.mkdir(parents=True, exist_ok=True)
                ac.grant(path, package, ac.MODIFY)
                ac.grant(path, user, ac.MODIFY)
            ac.set_ui_restrictions(job)
            env = {
                "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
                "TEMP": str(root / "tmp"),
                "TMP": str(root / "tmp"),
            }
            argv = [
                self.python,
                "-I",
                "-S",
                "-B",  # never write .pyc into the read-only source tree
                "-c",
                self.package_bootstrap(root, entry, args, import_paths),
            ]
            return ac.launch_in_appcontainer(
                argv,
                job,
                self.sandbox(package, capability),
                cwd=root,
                env=env,
                desktop=ac.workload_desktop(capability),
            )
        except OSError as exc:
            raise IsolationUnavailable(f"AppContainer launch failed: {exc}") from exc

    def sweep_orphans(self, known_workload_ids: set[str]) -> list[str]:
        """Delete UDCS workload profiles whose workload no longer exists (e.g. the agent
        died before a purge). Returns the names removed."""
        from udcs_agent.winplat import appcontainer as ac

        removed = []
        keep = {self.profile_name(w) for w in known_workload_ids}
        for name in ac.list_profiles(f"udcs.{self.scope}."):
            if name not in keep:
                try:
                    ac.delete_profile(name)
                    removed.append(name)
                except OSError:
                    logger.warning("could not delete orphan AppContainer %s", name, exc_info=True)
        return removed

    def release(self, workload_id: str, *, read_only: tuple[Path, ...] = ()) -> None:
        from udcs_agent.winplat import appcontainer as ac

        try:
            if read_only:
                package = ac.ensure_profile(self.profile_name(workload_id))
                for path in read_only:
                    ac.revoke(path, package)
            ac.delete_profile(self.profile_name(workload_id))
        except OSError:
            logger.warning("could not release AppContainer of %s", workload_id, exc_info=True)
