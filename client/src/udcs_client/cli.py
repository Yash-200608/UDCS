"""`udcs`: package a Python project, submit it, monitor it, fetch verified results.

Typical use:
    udcs login --server https://udcs.example.edu
    udcs init my-project            # writes udcs.toml and main.py
    udcs env list                   # approved, prebuilt environments
    udcs env use sci-py312          # pins come only from an approved environment
    udcs check                      # everything that can be known before uploading
    udcs submit                     # upload, register, submit (see below)
    udcs watch JOB                  # follow progress and logs
    udcs fetch JOB                  # download outputs, verifying every hash

Running user code is turned off on this deployment until the lab-image security
review and administrator node-eligibility controls are complete. Until then
`udcs submit` uploads and registers your package (the controller validates it) and
creates no job. Catalog jobs (`udcs submit --catalog cpu --units N`) run normally.
"""

from __future__ import annotations

import argparse
import getpass
import os
import random
import re
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

import httpx

from udcs_client import __version__
from udcs_client.api import Api
from udcs_client.check import Report, check_offline, check_online
from udcs_client.output import ClientError, Exit, human_bytes, sanitize
from udcs_client.results import CLIENT_MAX_BYTES, fetch_outputs, verify_catalog_result
from udcs_client.select import select_files
from udcs_client.session import (
    Config,
    Session,
    build_http,
    delete_session,
    load_config,
    load_session,
    resolve_ca_bundle,
    resolve_server,
    save_config,
    save_session,
    token_for,
    validate_server,
)
from udcs_client.spec import (
    SPEC_FILENAME,
    SpecError,
    find_project,
    initial_spec,
    load_spec,
    write_spec,
)
from udcs_shared.packages import DatasetRef, PackageKind, PackageManifest, policy_problems
from udcs_shared.protection import WorkloadClass
from udcs_shared.transfer import TransferError, VerificationError, manifest_from_files
from udcs_shared.transfer_http import ChunkedUploader
from udcs_shared.urls import origin

HttpFactory = Callable[[str, str | None, str | None], httpx.Client]
TERMINAL = {"succeeded", "failed", "cancelled"}
DISABLED_MESSAGE = (
    "Package {digest} is uploaded and registered; the controller validated it.\n"
    "Running user code is turned off on this deployment until the lab-image security "
    "review and administrator node-eligibility controls are complete. No job was created.\n"
    "Run `udcs submit` again after your administrator enables it; nothing will be re-uploaded."
)
ENTRY_STUB = '''"""Entry point of this UDCS package.

Inputs are read-only under inputs/<dataset name>/; write results under out/ only.
There is no network access while it runs.
"""

import json
from pathlib import Path

config = json.loads(Path("config.json").read_text())
Path("out").mkdir(exist_ok=True)
Path("out/result.txt").write_text(f"hello from UDCS, config={config}\\n")
'''


@dataclass
class Ctx:
    args: argparse.Namespace
    out: TextIO
    err: TextIO
    http_factory: HttpFactory
    sleep: Callable[[float], None]
    ask: Callable[[str], str]
    ask_secret: Callable[[str], str]
    _api: Api | None = field(default=None, repr=False)
    _http: httpx.Client | None = field(default=None, repr=False)
    _token: str | None = field(default=None, repr=False)

    def say(self, text: str = "") -> None:
        print(sanitize(text, secrets=(self._token or "",)), file=self.out)

    def warn(self, text: str) -> None:
        print(sanitize(text, secrets=(self._token or "",)), file=self.err)

    def connect(self) -> Api:
        if self._api is None:
            server = resolve_server(self.args.server)
            token = token_for(server)
            if token is None:
                raise ClientError("not logged in: run `udcs login`", Exit.USAGE)
            self._token = token
            self._http = self.http_factory(server, resolve_ca_bundle(self.args.ca_bundle), token)
            self._api = Api(self._http, token=token)
        return self._api

    @property
    def http(self) -> httpx.Client:
        self.connect()
        return self._http

    def confirm(self, question: str) -> bool:
        if getattr(self.args, "yes", False):
            return True
        try:
            return self.ask(f"{question} [y/N] ").strip().lower() in ("y", "yes")
        except EOFError:
            return False


def _project(ctx: Ctx) -> Path:
    directory = getattr(ctx.args, "directory", None)
    if directory:
        path = Path(directory)
        if not (path / SPEC_FILENAME).is_file():
            raise ClientError(f"no {SPEC_FILENAME} in {path}", Exit.INVALID)
        return path.resolve()
    try:
        return find_project(Path.cwd())
    except SpecError as exc:
        raise ClientError(str(exc), Exit.INVALID) from None


# -- auth --------------------------------------------------------------------------------------


def cmd_login(ctx: Ctx) -> int:
    config = load_config()
    server = validate_server(
        ctx.args.server
        or os.environ.get("UDCS_SERVER")
        or config.server
        or ctx.ask("Server (https://...): ")
    )
    ca_bundle = resolve_ca_bundle(ctx.args.ca_bundle)
    if ca_bundle:
        ca_bundle = str(Path(ca_bundle).resolve())  # remembered, so it must not be relative
        if not Path(ca_bundle).is_file():
            raise ClientError(f"CA bundle {ca_bundle} does not exist", Exit.USAGE)
    username = ctx.args.username or ctx.ask("Username: ").strip()
    password = ctx.ask_secret("Password: ")  # never from a flag or an environment variable
    api = Api(ctx.http_factory(server, ca_bundle, None))
    body = api.login(username, password)
    save_config(Config(server=server, ca_bundle=ca_bundle))
    save_session(
        Session(
            origin=origin(server),
            token=body["access_token"],
            expires_at=str(body["expires_at"]),
            username=body["user"]["username"],
        )
    )
    ctx.say(f"Logged in to {origin(server)} as {body['user']['username']}.")
    ctx.say(f"The session expires at {body['expires_at']}.")
    return Exit.OK


def cmd_logout(ctx: Ctx) -> int:
    """Revoke the *stored* session against the origin that issued it (never UDCS_TOKEN,
    never whatever --server says), then delete it. If the server cannot confirm the
    revocation, say so: the token may still work until it expires."""
    if os.environ.get("UDCS_TOKEN"):
        ctx.warn("note: UDCS_TOKEN is not managed by `udcs logout`; revoke it where it was issued")
    try:
        session = load_session()
    except ClientError:
        session = None  # unreadable: nothing we can revoke, but still remove it
    if session is None:
        delete_session()
        ctx.say("No stored session; nothing to revoke.")
        return Exit.OK
    http = ctx.http_factory(session.origin, resolve_ca_bundle(ctx.args.ca_bundle), session.token)
    revoked = Api(http, token=session.token).logout()
    delete_session()
    if not revoked:
        ctx.warn(
            f"warning: {session.origin} did not confirm the revocation; the deleted token may "
            f"still work until {session.expires_at}"
        )
        return Exit.SERVER
    ctx.say("Logged out: the session was revoked and deleted.")
    return Exit.OK


def cmd_whoami(ctx: Ctx) -> int:
    me = ctx.connect().me()
    session = load_session()
    ctx.say(f"{me['username']} ({me['role']}) on {resolve_server(ctx.args.server)}")
    if session is not None:
        ctx.say(f"session expires at {session.expires_at}")
    return Exit.OK


# -- project -----------------------------------------------------------------------------------


def _project_name(folder: str) -> str:
    """A valid package name from a folder name ("My Analysis" -> "My-Analysis")."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", folder).strip("-._")[:100]
    return cleaned or "project"


def cmd_init(ctx: Ctx) -> int:
    directory = Path(ctx.args.directory or ".")
    directory.mkdir(parents=True, exist_ok=True)
    spec_path = directory / SPEC_FILENAME
    entry_path = directory.joinpath(*ctx.args.entry.split("/"))
    for path in (spec_path, entry_path):
        if path.exists():
            raise ClientError(f"{path} already exists; not overwritten", Exit.USAGE)
    name = ctx.args.name or _project_name(directory.resolve().name)
    try:
        spec = initial_spec(name, ctx.args.entry)
    except ValueError as exc:
        raise ClientError(f"invalid project: {sanitize(exc)}", Exit.INVALID) from None
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    entry_path.write_text(ENTRY_STUB, encoding="utf-8")
    write_spec(spec_path, spec)
    ctx.say(f"Created {spec_path} and {entry_path}.")
    ctx.say("Next: `udcs env list` to choose an approved environment, then `udcs check`.")
    return Exit.OK


def _print_report(ctx: Ctx, report: Report) -> None:
    for name, count in sorted(report.excluded.items()):
        ctx.say(f"excluded: {count} x {name}")
    for warning in report.warnings:
        ctx.warn(f"warning: {warning}")
    for notice in report.notices:
        ctx.say(f"note: {notice}")
    for problem in report.problems:
        ctx.warn(f"error: {problem}")
    if report.manifest is not None and not report.problems:
        m = report.manifest
        ctx.say(f"package {m.name} {m.version}: {len(m.files)} files, {human_bytes(m.total_bytes)}")
        for path, size in report.largest():
            ctx.say(f"  {human_bytes(size):>10}  {path}")
        ctx.say(f"digest {m.digest()}")


def _checked(ctx: Ctx, *, online: bool = True) -> Report:
    report = check_offline(_project(ctx))
    if online and report.manifest is not None and not report.problems:
        check_online(report, ctx.connect())
    return report


def cmd_check(ctx: Ctx) -> int:
    report = _checked(ctx, online=not ctx.args.offline)
    if ctx.args.offline:
        ctx.say("note: offline; policy, environment and dataset checks were skipped")
    _print_report(ctx, report)
    if ctx.args.files and report.manifest is not None:
        for f in report.manifest.files:
            ctx.say(f"{f.sha256[:12]}  {f.size:>12}  {f.path}")
    if ctx.args.manifest_out and report.manifest is not None:
        Path(ctx.args.manifest_out).write_bytes(report.manifest.canonical_bytes())
    if not report.ok:
        return Exit.INVALID
    ctx.say("check passed")
    return Exit.OK


def _upload(ctx: Ctx, manifest: PackageManifest, paths: dict[str, Path]) -> tuple[int, int]:
    """Upload every file the manifest names, from the bytes that were hashed. Files the
    researcher already stored cost nothing. Returns (files sent, bytes on the wire)."""
    session = load_session()
    if session is not None and 0 < session.expires_in_seconds() < 15 * 60:
        ctx.warn(
            "warning: your session expires in under 15 minutes; `udcs login` first if this is large"
        )
    uploader = ChunkedUploader(ctx.http, prefix="/blobs")
    sent = wire = 0
    for item in manifest.files:
        try:
            stats = uploader.upload(paths[item.path], sha256=item.sha256, size=item.size)
        except VerificationError as exc:
            raise ClientError(f"{item.path}: {exc}", Exit.VERIFICATION) from None
        except TransferError as exc:
            raise ClientError(f"{item.path}: upload failed: {exc}") from None
        if not stats.skipped:
            sent += 1
            wire += stats.sent_bytes
    return sent, wire


def _push(ctx: Ctx, report: Report) -> str:
    manifest = report.manifest
    sent, wire = _upload(ctx, manifest, report.paths)
    registered = ctx.connect().register(manifest)
    if registered["digest"] != manifest.digest():
        raise ClientError("the controller registered a different digest", Exit.VERIFICATION)
    ctx.say(
        f"uploaded {sent} files ({human_bytes(wire)} on the wire); registered {manifest.digest()}"
    )
    return manifest.digest()


def cmd_push(ctx: Ctx) -> int:
    report = _checked(ctx)
    _print_report(ctx, report)
    if not report.ok:
        return Exit.INVALID
    if not ctx.confirm("Upload and register this package?"):
        ctx.say("nothing uploaded")
        return Exit.USAGE
    _push(ctx, report)
    return Exit.OK


def cmd_submit(ctx: Ctx) -> int:
    api = ctx.connect()
    if ctx.args.catalog:
        job = api.submit(
            {
                "name": ctx.args.name or "",
                "kind": ctx.args.catalog,
                "total_units": ctx.args.units,
                "memory_mb": ctx.args.memory_mb,
            }
        )
        ctx.say(f"submitted catalog job {job['id']} ({job['kind']}, {job['total_units']} units)")
        ctx.say(f"follow it with: udcs watch {job['id']}")
        return Exit.OK
    report = _checked(ctx)
    _print_report(ctx, report)
    if not report.ok:
        return Exit.INVALID
    if not ctx.confirm("Upload, register and submit this package?"):
        ctx.say("nothing uploaded")
        return Exit.USAGE
    digest = _push(ctx, report)
    if not report.user_code_enabled:
        ctx.say(DISABLED_MESSAGE.format(digest=digest))
        return Exit.DISABLED  # no POST /jobs is sent
    try:
        job = api.submit(
            {
                "name": ctx.args.name or report.spec.project.name,
                "kind": report.spec.project.resource_class.value,
                "total_units": 1,  # no meaning for user code yet (ADR 0002 open decision)
                "memory_mb": ctx.args.memory_mb,
                "package": digest,
            }
        )
    except ClientError as exc:
        if exc.code == Exit.DISABLED:
            ctx.say(DISABLED_MESSAGE.format(digest=digest))
        raise
    ctx.say(f"submitted job {job['id']} for package {digest}")
    ctx.say(f"follow it with: udcs watch {job['id']}")
    return Exit.OK


# -- environments and datasets ------------------------------------------------------------------


def _resolve(items: list[dict], ref: str, what: str) -> dict:
    """A digest, or a name / name==version matching exactly one approved item."""
    exact = [i for i in items if i["digest"] == ref.lower()]
    if exact:
        return exact[0]
    if len(ref) >= 8 and all(c in "0123456789abcdef" for c in ref.lower()):
        prefixed = [i for i in items if i["digest"].startswith(ref.lower())]
        if len(prefixed) == 1:
            return prefixed[0]
        if len(prefixed) > 1:
            raise ClientError(
                f"digest prefix {ref!r} is ambiguous; give more characters", Exit.USAGE
            )
    name, _, version = ref.partition("==")
    matches = [
        i
        for i in items
        if i["name"].casefold() == name.casefold() and (not version or i["version"] == version)
    ]
    if not matches:
        raise ClientError(
            f"no approved {what} matches {ref!r} (see `udcs {what} list`)", Exit.USAGE
        )
    if len(matches) > 1:
        listed = ", ".join(f"{m['name']}=={m['version']} ({m['digest'][:12]})" for m in matches)
        raise ClientError(
            f"{ref!r} matches several {what}s: {listed}; use name==version or a digest", Exit.USAGE
        )
    return matches[0]


def _print_items(ctx: Ctx, items: list[dict]) -> None:
    if not items:
        ctx.say("none approved yet")
    for i in items:
        extra = f"python {i['python']} {i['platform']}" if i.get("platform") else ""
        ctx.say(
            f"{i['digest'][:12]}  {i['name']}=={i['version']}  "
            f"{human_bytes(i['total_bytes'])}  {extra}"
        )


def cmd_env_list(ctx: Ctx) -> int:
    _print_items(ctx, ctx.connect().list_packages("environment"))
    return Exit.OK


def cmd_env_show(ctx: Ctx) -> int:
    api = ctx.connect()
    item = _resolve(api.list_packages("environment"), ctx.args.ref, "env")
    body = api.package(item["digest"])
    manifest = PackageManifest.model_validate(body["manifest"])
    ctx.say(f"{manifest.name}=={manifest.version}  python {manifest.python}  {manifest.platform}")
    ctx.say(f"digest {item['digest']}")
    for req in manifest.lock:
        ctx.say(f"  {req.name}=={req.version}")
    return Exit.OK


def cmd_env_use(ctx: Ctx) -> int:
    project = _project(ctx)
    spec = load_spec(project / SPEC_FILENAME)
    item = _resolve(ctx.connect().list_packages("environment"), ctx.args.ref, "env")
    updated = spec.model_copy(
        update={
            "environment": spec.environment.model_copy(update={"digest": item["digest"]}),
            "project": spec.project.model_copy(update={"python": item["python"]}),
        }
    )
    write_spec(project / SPEC_FILENAME, updated)
    ctx.say(f"using environment {item['name']}=={item['version']} (python {item['python']})")
    ctx.say('declare the packages you import as environment.requirements, e.g. "numpy==2.1.3"')
    ctx.say(f"(`udcs env show {item['name']}` lists what it provides)")
    return Exit.OK


def cmd_dataset_list(ctx: Ctx) -> int:
    _print_items(ctx, ctx.connect().list_packages("dataset"))
    return Exit.OK


def cmd_dataset_add(ctx: Ctx) -> int:
    project = _project(ctx)
    spec = load_spec(project / SPEC_FILENAME)
    item = _resolve(ctx.connect().list_packages("dataset"), ctx.args.ref, "dataset")
    if any(d.name.casefold() == ctx.args.name.casefold() for d in spec.datasets):
        raise ClientError(f"a dataset named {ctx.args.name!r} is already attached", Exit.USAGE)
    try:
        ref = DatasetRef(name=ctx.args.name, digest=item["digest"])
    except ValueError as exc:
        raise ClientError(f"invalid dataset name: {sanitize(exc)}", Exit.USAGE) from None
    write_spec(project / SPEC_FILENAME, spec.model_copy(update={"datasets": [*spec.datasets, ref]}))
    ctx.say(f"attached {item['name']}=={item['version']} at inputs/{ctx.args.name}/ (read-only)")
    return Exit.OK


def cmd_dataset_push(ctx: Ctx) -> int:
    root = Path(ctx.args.path)
    if not root.is_dir():
        raise ClientError(f"{root} is not a directory", Exit.USAGE)
    selection = select_files(root, ["**"], ctx.args.allow_flagged or [])
    for name, count in sorted(selection.excluded.items()):
        ctx.say(f"excluded: {count} x {name}")
    problems = selection.problems + [
        f"{f} (heuristic, not a guarantee; if it is a false positive, re-run with "
        "--allow-flagged PATH)"
        for f in selection.flagged
    ]
    if not selection.files:
        problems.append("the directory has no files to package")
    if problems:
        for problem in problems:
            ctx.warn(f"error: {problem}")
        return Exit.INVALID
    try:
        manifest, paths = manifest_from_files(
            selection.files, kind=PackageKind.DATASET, name=ctx.args.name, version=ctx.args.version
        )
    except (ValueError, TransferError) as exc:
        ctx.warn(f"error: {sanitize(exc)[:500]}")
        return Exit.INVALID
    ctx.say(
        f"dataset {manifest.name}=={manifest.version}: {len(manifest.files)} files, "
        f"{human_bytes(manifest.total_bytes)}"
    )
    refused = policy_problems(manifest, ctx.connect().policy())  # before any byte is sent
    if refused:
        for problem in refused:
            ctx.warn(f"error: policy: {problem}")
        return Exit.INVALID
    if not ctx.confirm("Upload and register this dataset?"):
        ctx.say("nothing uploaded")
        return Exit.USAGE
    _upload(ctx, manifest, paths)
    ctx.connect().register(manifest)
    ctx.say(f"registered dataset {manifest.digest()}")
    ctx.say(
        "It is awaiting administrator approval: give them this digest. "
        "Until then no package can use it."
    )
    return Exit.OK


# -- jobs --------------------------------------------------------------------------------------


def _job_line(job: dict) -> str:
    if job.get("package"):
        progress = f"attempt {job['attempt']}, {job['cpu_seconds']:.0f} CPU s"  # no fake percentage
        if job.get("exit_code") is not None:
            progress += f", exit code {job['exit_code']}"
    else:
        progress = f"{job['progress'] * 100:.0f}% ({job['units_done']}/{job['total_units']} units)"
    local = f" [{job['local_state']}]" if job.get("local_state") else ""
    kind = f"package {job['package'][:12]}" if job.get("package") else f"catalog {job['kind']}"
    return f"{job['id']}  {job['state']}{local}  {kind}  {progress}"


def cmd_jobs(ctx: Ctx) -> int:
    jobs = ctx.connect().jobs(state=ctx.args.state, limit=ctx.args.limit)
    if not jobs:
        ctx.say("no jobs")
    for job in jobs:
        ctx.say(_job_line(job))
    return Exit.OK


def cmd_status(ctx: Ctx) -> int:
    job = ctx.connect().job(ctx.args.job)
    ctx.say(_job_line(job))
    if job.get("error"):
        ctx.say(f"error: {job['error']}")
    return Exit.OK


def _print_logs(ctx: Ctx, lines: list[dict]) -> int | None:
    last = None
    for line in lines:
        ctx.say(f"{line['at']}  [{line['source']}] {line['message']}")
        last = line["id"]
    return last


LOG_PAGE = 500


def _drain_logs(ctx: Ctx, api: Api, job_id: str, after: int | None) -> int | None:
    """Print every log line after `after`, page by page; return the newest id."""
    while True:
        lines = api.logs(job_id, after=after, limit=LOG_PAGE)
        newest = _print_logs(ctx, lines)
        if newest is not None:
            after = newest
        if len(lines) < LOG_PAGE:
            return after


def _follow(ctx: Ctx, job_id: str, *, show_status: bool) -> int:
    """Poll with backoff (2 s doubling to 30 s, jittered, reset on any change). A
    network failure or a 5xx is retried; anything else ends the command. When the job
    ends, the remaining log lines are printed before returning."""
    api = ctx.connect()
    jitter = random.Random()  # noqa: S311 -- spreading polls, not security
    interval, after, last, failures = 2.0, None, None, 0
    try:
        while True:
            try:
                job = api.job(job_id)
                newest = _drain_logs(ctx, api, job_id, after)
            except ClientError as exc:
                if not exc.transient or failures >= 8:
                    raise
                failures += 1
                ctx.warn(f"warning: {exc}; retrying")
                interval = min(30.0, interval * 2)
                ctx.sleep(interval * jitter.uniform(0.8, 1.2))
                continue
            failures = 0
            snapshot = (job["state"], job["units_done"], job.get("local_state"), job["attempt"])
            changed = newest != after or snapshot != last
            after = newest
            if show_status and snapshot != last:
                ctx.say(_job_line(job))
            last = snapshot
            if job["state"] in TERMINAL:
                after = _drain_logs(ctx, api, job_id, after)  # lines written as it ended
                if job.get("error"):
                    ctx.say(f"error: {job['error']}")
                return Exit.OK if job["state"] == "succeeded" else Exit.JOB_FAILED
            interval = 2.0 if changed else min(30.0, interval * 2)
            ctx.sleep(interval * jitter.uniform(0.8, 1.2))
    except KeyboardInterrupt:
        ctx.say("detached; the job keeps running (cancel it with `udcs cancel`)")
        return Exit.OK


def cmd_watch(ctx: Ctx) -> int:
    return _follow(ctx, ctx.args.job, show_status=True)


def cmd_logs(ctx: Ctx) -> int:
    if ctx.args.follow:
        return _follow(ctx, ctx.args.job, show_status=False)
    _drain_logs(ctx, ctx.connect(), ctx.args.job, None)  # every line, page by page
    return Exit.OK


def cmd_cancel(ctx: Ctx) -> int:
    if not ctx.confirm(f"Cancel job {ctx.args.job}?"):
        ctx.say("not cancelled")
        return Exit.USAGE
    job = ctx.connect().cancel(ctx.args.job)
    ctx.say(_job_line(job))
    return Exit.OK


def cmd_fetch(ctx: Ctx) -> int:
    api = ctx.connect()
    job = api.job(ctx.args.job)
    if job.get("id") != ctx.args.job:  # never use a controller-supplied id in paths or URLs
        raise ClientError("the controller answered for a different job", Exit.VERIFICATION)
    if job["state"] != "succeeded" and not ctx.args.allow_incomplete:
        raise ClientError(
            f"the job is {job['state']}; results are fetched from succeeded jobs "
            "(--allow-incomplete fetches what a failed job reported)",
            Exit.USAGE,
        )
    if not job.get("package"):
        ok, detail = verify_catalog_result(job, api.result(ctx.args.job))
        ctx.say(("verified: " if ok else "NOT verified: ") + detail)
        return Exit.OK if ok else Exit.VERIFICATION
    manifest = api.outputs(ctx.args.job)
    if manifest is None:
        ctx.say("the job reported no outputs")
        return Exit.OK
    target = Path(ctx.args.output or Path("udcs-results") / ctx.args.job)
    report = fetch_outputs(
        api,
        ctx.http,
        job,
        manifest,
        target,
        resume=ctx.args.resume,
        max_bytes=min(api.policy().max_output_bytes, ctx.args.max_bytes),
    )
    ctx.say(
        f"{report.files} files in {report.target} "
        f"({human_bytes(report.downloaded_bytes)} downloaded)"
    )
    ctx.say(
        f"All {report.files} files match the hashes the node reported. This proves the "
        "download is intact, not that the node computed it correctly."
    )
    return Exit.OK


# -- parser ------------------------------------------------------------------------------------


def _job_id(value: str) -> str:
    """Job ids are UUIDs. Validated here because they become URL paths and the default
    fetch directory: nothing the user or the controller sends may smuggle a path."""
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a job id") from None


# -- administrators: user-code eligibility (docs/operations/node-eligibility.md) -------------


def _admin_call(ctx: Ctx, method: str, path: str, **kwargs):
    api = ctx.connect()
    response = api._call(method, path, **kwargs)
    if response.status_code == 403:
        raise ClientError("this needs an administrator account (manage_nodes)", Exit.USAGE)
    if response.status_code == 404:
        raise ClientError("node not found", Exit.USAGE)
    if response.status_code >= 400:
        raise ClientError(f"refused: {api._detail(response)}", Exit.INVALID)
    return response.json()


def cmd_admin_nodes(ctx: Ctx) -> int:
    for n in _admin_call(ctx, "GET", "/admin/nodes"):
        flag = "ELIGIBLE" if n.get("user_code_allowed") else "not eligible"
        blocked = f" (blocked: {n['user_code_blocked']})" if n.get("user_code_blocked") else ""
        ctx.say(f"{n['id']}  {n['hostname']}  {n['admin_state']}  {flag}{blocked}")
    return Exit.OK


def cmd_admin_audit_upload(ctx: Ctx) -> int:
    from udcs_shared.exposure import ExposureReport

    try:
        report = ExposureReport.model_validate_json(Path(ctx.args.report).read_bytes())
    except (OSError, ValueError) as exc:
        raise ClientError(f"not an exposure report: {sanitize(exc)[:300]}", Exit.INVALID) from None
    body = _admin_call(
        ctx,
        "POST",
        f"/admin/nodes/{ctx.args.node}/exposure-audits",
        json=report.model_dump(mode="json"),
    )
    ctx.say(f"recorded audit {body['id']} (sha256 {body['sha256'][:16]})")
    ctx.say(f"image {body['image']}, run as {body['runner']}")
    ctx.say("PASSED" if body["passed"] else f"FAILED: {body['violation_count']} violations")
    for line in body.get("violations", [])[:30]:
        ctx.say(f"  {line}")
    return Exit.OK if body["passed"] else Exit.VERIFICATION


def cmd_admin_audits(ctx: Ctx) -> int:
    for a in _admin_call(ctx, "GET", f"/admin/nodes/{ctx.args.node}/exposure-audits"):
        verdict = "passed" if a["passed"] else f"{a['violation_count']} violations"
        ctx.say(f"{a['uploaded_at']}  {a['image']}  {a['runner']}  {verdict}  {a['sha256'][:16]}")
    return Exit.OK


def cmd_admin_user_code(ctx: Ctx) -> int:
    allowed = ctx.args.action == "allow"
    if allowed and not ctx.confirm(
        f"Allow node {ctx.args.node} to run researchers' code? This is audited."
    ):
        ctx.say("not changed")
        return Exit.USAGE
    body = _admin_call(
        ctx,
        "POST",
        f"/admin/nodes/{ctx.args.node}/user-code",
        json={"allowed": allowed, "reason": ctx.args.reason},
    )
    if allowed:
        ctx.say(f"node {body['hostname']} is eligible for image {body['user_code_image']}")
    else:
        ctx.say(f"node {body['hostname']} is no longer eligible; running package jobs move away")
    return Exit.OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="udcs", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--version", action="version", version=f"udcs {__version__}")
    parser.add_argument(
        "--server", help="controller URL (https:// only); default: from `udcs login`"
    )
    parser.add_argument(
        "--ca-bundle", help="CA certificate file for a campus-internal TLS certificate"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, func, help_: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_)
        p.set_defaults(func=func)
        return p

    p = add("login", cmd_login, "log in (the password is read from a hidden prompt only)")
    p.add_argument("--username")
    add("logout", cmd_logout, "revoke the session and delete it locally")
    add("whoami", cmd_whoami, "show who you are logged in as")

    p = add("init", cmd_init, "create udcs.toml and an entry script")
    p.add_argument("directory", nargs="?")
    p.add_argument("--name")
    p.add_argument("--entry", default="main.py")

    for name, func, help_ in (
        ("check", cmd_check, "validate the project without uploading anything"),
        ("push", cmd_push, "check, upload and register the package (no job)"),
        ("submit", cmd_submit, "check, upload, register and submit the package"),
    ):
        p = add(name, func, help_)
        p.add_argument("-C", "--directory", help="project directory (default: nearest udcs.toml)")
        if name == "check":
            p.add_argument("--offline", action="store_true", help="skip the server checks")
            p.add_argument("--files", action="store_true", help="list every packaged file")
            p.add_argument("--manifest-out", help="write the canonical manifest here")
        else:
            p.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
        if name == "submit":
            p.add_argument("--name", help="job name")
            p.add_argument("--memory-mb", type=int, default=256)
            p.add_argument(
                "--catalog",
                choices=[w.value for w in WorkloadClass],
                help="submit a built-in catalog workload instead",
            )
            p.add_argument("--units", type=int, default=100_000, help="catalog work units")

    env = sub.add_parser("env", help="approved environments").add_subparsers(
        dest="env", required=True
    )
    env.add_parser("list").set_defaults(func=cmd_env_list)
    p = env.add_parser("show")
    p.add_argument("ref", help="digest, name or name==version")
    p.set_defaults(func=cmd_env_show)
    p = env.add_parser("use", help="set the project's environment (rewrites udcs.toml)")
    p.add_argument("ref")
    p.add_argument("-C", "--directory")
    p.set_defaults(func=cmd_env_use)

    ds = sub.add_parser("dataset", help="approved datasets").add_subparsers(
        dest="dataset", required=True
    )
    ds.add_parser("list").set_defaults(func=cmd_dataset_list)
    p = ds.add_parser("add", help="attach an approved dataset (rewrites udcs.toml)")
    p.add_argument("name", help="mounted read-only at inputs/<name>/")
    p.add_argument("ref", help="digest, name or name==version")
    p.add_argument("-C", "--directory")
    p.set_defaults(func=cmd_dataset_add)
    p = ds.add_parser("push", help="upload a directory as a dataset (needs administrator approval)")
    p.add_argument("path")
    p.add_argument("--name", required=True)
    p.add_argument("--version", required=True)
    p.add_argument(
        "--allow-flagged",
        action="append",
        metavar="PATH",
        help="exempt a file from the secret heuristic",
    )
    p.add_argument("-y", "--yes", action="store_true")
    p.set_defaults(func=cmd_dataset_push)

    admin = sub.add_parser("admin", help="administrators: node eligibility for user code")
    asub = admin.add_subparsers(dest="admin", required=True)
    asub.add_parser("nodes", help="nodes and their eligibility").set_defaults(func=cmd_admin_nodes)
    p = asub.add_parser("audit-upload", help="record an exposure report for a node")
    p.add_argument("node", type=_job_id, help="node id")
    p.add_argument("report", help="report JSON from `udcs-agent audit-exposure`")
    p.set_defaults(func=cmd_admin_audit_upload)
    p = asub.add_parser("audits", help="a node's exposure audit history")
    p.add_argument("node", type=_job_id)
    p.set_defaults(func=cmd_admin_audits)
    p = asub.add_parser("user-code", help="grant or revoke a node's eligibility")
    p.add_argument("action", choices=["allow", "revoke"])
    p.add_argument("node", type=_job_id)
    p.add_argument("--reason", required=True, help="recorded in the audit log (3-200 chars)")
    p.add_argument("-y", "--yes", action="store_true")
    p.set_defaults(func=cmd_admin_user_code)

    p = add("jobs", cmd_jobs, "list your jobs")
    p.add_argument(
        "--state", choices=["queued", "assigned", "running", "succeeded", "failed", "cancelled"]
    )
    p.add_argument("--limit", type=int, default=50)
    for name, func, help_ in (
        ("status", cmd_status, "show one job"),
        ("watch", cmd_watch, "follow a job until it ends (Ctrl-C detaches; it does not cancel)"),
        ("logs", cmd_logs, "show a job's log"),
        ("cancel", cmd_cancel, "cancel a job"),
        ("fetch", cmd_fetch, "download a job's results, verifying every hash"),
    ):
        p = add(name, func, help_)
        p.add_argument("job", type=_job_id, help="job id (a UUID)")
        if name == "logs":
            p.add_argument("-f", "--follow", action="store_true")
        if name == "cancel":
            p.add_argument("-y", "--yes", action="store_true")
        if name == "fetch":
            p.add_argument("-o", "--output", help="target directory (default: udcs-results/<job>)")
            p.add_argument("--resume", action="store_true", help="continue an interrupted fetch")
            p.add_argument("--allow-incomplete", action="store_true")
            p.add_argument(
                "--max-bytes",
                type=int,
                default=CLIENT_MAX_BYTES,
                help=f"refuse outputs larger than this (default {CLIENT_MAX_BYTES // 2**30} GiB)",
            )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    http_factory: HttpFactory = build_http,
    out: TextIO | None = None,
    err: TextIO | None = None,
    sleep: Callable[[float], None] = time.sleep,
    ask: Callable[[str], str] = input,
    ask_secret: Callable[[str], str] = getpass.getpass,
) -> int:
    args = build_parser().parse_args(argv)
    ctx = Ctx(
        args=args,
        out=out or sys.stdout,
        err=err or sys.stderr,
        http_factory=http_factory,
        sleep=sleep,
        ask=ask,
        ask_secret=ask_secret,
    )
    try:
        return int(args.func(ctx))
    except ClientError as exc:
        ctx.warn(f"udcs: {exc}")
        return int(exc.code)
    except SpecError as exc:
        for problem in exc.problems:
            ctx.warn(f"error: {problem}")
        return int(Exit.INVALID)


if __name__ == "__main__":
    sys.exit(main())
