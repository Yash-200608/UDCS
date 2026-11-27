"""`udcs-agent` command line.

discover        print detected hardware and telemetry
enroll          enroll this machine with a lab enrollment key (env var or prompt)
run             run the agent in the foreground (development; production uses the service)
status          print the governor's last status
workload        add / list / remove built-in synthetic validation workloads (admin only)
diagnose-gpu    run the GPU execution-context experiment (E1) in the *current* context
helper          run the per-session helper (normally started at logon by pythonw)
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from udcs_agent.communication.client import AgentError, ControllerClient, EnrollmentRejected
from udcs_agent.config import (
    CREDENTIAL_FILENAME,
    AgentConfig,
    ConfigError,
    default_data_dir,
    save_config,
)
from udcs_agent.credentials import CredentialStore, NodeCredential
from udcs_agent.discovery import collect_inventory
from udcs_agent.discovery.nvidia import Nvml
from udcs_agent.monitoring.telemetry import TelemetryCollector
from udcs_shared.logs import configure_logging

logger = logging.getLogger("udcs.agent")

TOKEN_ENV = "UDCS_ENROLLMENT_TOKEN"  # noqa: S105 (env var name)


def cmd_discover(args: argparse.Namespace) -> int:
    with Nvml() as nvml:
        inventory = collect_inventory(nvml)
        telemetry = TelemetryCollector(
            nvml, args.data_dir if args.data_dir.exists() else Path.cwd()
        )
        print(
            json.dumps(
                {
                    "inventory": inventory.model_dump(mode="json"),
                    "fingerprint": inventory.fingerprint(),
                    "telemetry": telemetry.collect().model_dump(mode="json"),
                },
                indent=2,
            )
        )
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    store = CredentialStore(args.data_dir / CREDENTIAL_FILENAME)
    if store.exists() and not args.force:
        sys.exit(f"this machine is already enrolled ({store.path}); use --force to re-enroll")
    try:
        config = AgentConfig(
            controller_url=args.controller_url,
            ca_bundle=args.ca_bundle,
            allow_insecure_http=args.allow_insecure_http,
            node_name=args.name,
        )
    except ConfigError as exc:
        sys.exit(f"configuration error: {exc}")
    # Never accept the key on argv: it would leak into shell history / process lists.
    key = os.environ.get(TOKEN_ENV) or getpass.getpass("Lab enrollment key: ")
    save_config(args.data_dir, config)  # fail on an unwritable data dir *before* using a key
    with Nvml() as nvml, ControllerClient(config) as client:
        inventory = collect_inventory(nvml)
        try:
            enrolled = client.enroll(key.strip(), inventory, args.name)
        except EnrollmentRejected as exc:
            sys.exit(f"enrollment rejected: {exc}")
        except AgentError as exc:
            sys.exit(f"enrollment failed: {exc}")
    # Only the node's own credential is stored. The lab key is never written to disk.
    store.save(NodeCredential(node_id=enrolled.node_id, secret=enrolled.node_credential))
    print(
        f"enrolled as node {enrolled.node_id} ({enrolled.admin_state.value}); "
        f"credential stored in {store.path}"
    )
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from udcs_agent.app import AgentApp

    stop = threading.Event()
    app = AgentApp(args.data_dir, stop=stop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    return app.run()


def cmd_status(args: argparse.Namespace) -> int:
    path = args.data_dir / "status" / "governor.json"
    try:
        print(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"no status yet at {path} (is the agent running?)")
    return 0


def cmd_workload(args: argparse.Namespace) -> int:
    from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec

    registry = args.data_dir / "workloads" / "registry.json"
    if args.action == "list":
        print(registry.read_text(encoding="utf-8") if registry.exists() else '{"workloads": []}')
        return 0
    # Queued for the running agent (or its next start): registry.json has one writer.
    if args.action == "add":
        spec = WorkloadSpec(
            id=args.id, kind=args.kind, total_units=args.total_units, memory_mb=args.memory_mb
        )
        WorkloadManager.queue_request(args.data_dir, "add", spec=spec)
    else:
        WorkloadManager.queue_request(args.data_dir, "remove", workload_id=args.id)
    print(f"{args.action} {args.id}: queued; the agent applies it within a few seconds")
    return 0


def cmd_diagnose_gpu(args: argparse.Namespace) -> int:
    from udcs_agent.diagnostics.gpu_matrix import run_matrix

    print(json.dumps(run_matrix(args.data_dir / "diagnostics" / "work"), indent=1))
    return 0


def cmd_audit_exposure(args: argparse.Namespace) -> int:
    """Run the AppContainer exposure audit on this machine (ADR 0001 gate 2)."""
    import json
    import os

    from udcs_agent.diagnostics.exposure_audit import run_audit
    from udcs_shared.exposure import summary

    if args.data_dir:
        data_dir = Path(args.data_dir)
    else:  # a scratch area the current user can write; nothing in the agent's data dir
        data_dir = Path(os.environ.get("LOCALAPPDATA", ".")) / "UDCS" / "exposure-audit"
    data_dir.mkdir(parents=True, exist_ok=True)
    report, _plan = run_audit(data_dir)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.model_dump_json(indent=1), encoding="utf-8")
    result = summary(report)
    print(
        json.dumps(
            {
                k: result[k]
                for k in ("passed", "violation_count", "reachable", "truncated", "image", "runner")
            },
            indent=1,
        )
    )
    for line in result["violations"][:50]:
        print("VIOLATION:", line)
    print(f"report: {out}")
    if args.summary_out:
        from udcs_agent.diagnostics.context import labelled

        result.pop("runner", None)  # carries a user name; the identity block replaces it
        # An exposure audit is evidence about this image only when run as LocalSystem.
        wrapped = labelled("exposure-audit", result, evidence_context=True)
        summary_out = Path(args.summary_out)
        summary_out.parent.mkdir(parents=True, exist_ok=True)
        summary_out.write_text(json.dumps(wrapped, indent=1), encoding="utf-8")
        print(f"summary ({'evidence' if wrapped['evidence'] else 'diagnostic'}): {summary_out}")
    return 0 if result["passed"] else 1


def cmd_isolation_selftest(args: argparse.Namespace) -> int:
    """The isolation self-test in THIS process. Always a diagnostic: acceptance evidence
    comes only from the installed service (m2_isolation_service_acceptance.ps1)."""
    import json
    import os

    from udcs_agent.diagnostics.context import labelled
    from udcs_agent.diagnostics.isolation import detect_isolation, run_selftest
    from udcs_agent.workloads.isolation import AppContainerIsolation

    data_dir = Path(
        args.data_dir or Path(os.environ.get("LOCALAPPDATA", ".")) / "UDCS" / "isolation-selftest"
    )
    data_dir.mkdir(parents=True, exist_ok=True)
    report = run_selftest(data_dir / "scratch", AppContainerIsolation(data_dir))
    report["capabilities"] = [c.model_dump() for c in detect_isolation(data_dir)]
    wrapped = labelled("isolation-selftest", report, evidence_context=False)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(wrapped, indent=1), encoding="utf-8")
    print(f"context: {wrapped['identity']['context']}  passed: {report.get('passed')}")
    for check in report.get("checks", []):
        print(f"{'PASS' if check['pass'] else 'FAIL'}  {check['name']}")
    print(f"kill_tree: {report.get('kill_tree', {}).get('pass')}")
    print(f"result (diagnostic only): {out}")
    return 0 if report.get("passed") else 1


def cmd_helper(_args: argparse.Namespace) -> int:
    from udcs_agent.session_helper import main

    return main()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="udcs-agent", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--plain-logs", action="store_true", help="human-readable logs")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("discover").set_defaults(func=cmd_discover)

    p = sub.add_parser("enroll", help=f"enroll this machine (key from ${TOKEN_ENV} or prompt)")
    p.add_argument("--controller-url", required=True)
    p.add_argument("--ca-bundle", type=Path, help="PEM CA certificate(s) to trust")
    p.add_argument("--name", help="node name shown to administrators")
    p.add_argument("--allow-insecure-http", action="store_true", help="development only")
    p.add_argument("--force", action="store_true", help="replace an existing enrollment")
    p.set_defaults(func=cmd_enroll)

    sub.add_parser("run").set_defaults(func=cmd_run)
    sub.add_parser("status").set_defaults(func=cmd_status)

    p = sub.add_parser("workload", help="manage built-in synthetic validation workloads")
    p.add_argument("action", choices=["add", "list", "remove"])
    p.add_argument("--id", default="")
    p.add_argument("--kind", choices=["cpu", "memory", "disk", "gpu"], default="cpu")
    p.add_argument("--total-units", type=int, default=10**9)
    p.add_argument("--memory-mb", type=int, default=256)
    p.set_defaults(func=cmd_workload)

    sub.add_parser("diagnose-gpu").set_defaults(func=cmd_diagnose_gpu)
    sub.add_parser("helper").set_defaults(func=cmd_helper)
    p = sub.add_parser("audit-exposure", help="what a UDCS AppContainer can reach on this image")
    p.add_argument("--out", required=True, help="where to write the JSON report")
    p.add_argument("--data-dir", help="scratch/runtime directory (default: per-user)")
    p.add_argument("--summary-out", help="also write a labelled summary (machine, image, identity)")
    p.set_defaults(func=cmd_audit_exposure)
    p = sub.add_parser(
        "isolation-selftest", help="isolation self-test in this process (diagnostic)"
    )
    p.add_argument("--out", required=True)
    p.add_argument("--data-dir", help="scratch/runtime directory (default: per-user)")
    p.set_defaults(func=cmd_isolation_selftest)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, json_output=not args.plain_logs)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
