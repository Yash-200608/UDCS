"""`udcs-controller` command line: migrate, bootstrap, serve."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import sys
from datetime import timedelta

from pydantic import ValidationError
from sqlalchemy import select

from udcs_controller.config import Settings

BOOTSTRAP_PASSWORD_ENV = "UDCS_BOOTSTRAP_ADMIN_PASSWORD"  # noqa: S105 (env var name)


def _settings() -> Settings:
    try:
        return Settings()  # type: ignore[call-arg]
    except ValidationError as exc:
        missing = ", ".join(f"UDCS_{'_'.join(map(str, e['loc'])).upper()}" for e in exc.errors())
        sys.exit(f"configuration error ({missing}): {exc.errors()[0]['msg']}")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cmd_migrate(_args: argparse.Namespace) -> int:
    from udcs_controller.database.migrate import upgrade_to_head
    from udcs_controller.database.session import create_db_engine

    engine = create_db_engine(_settings().database_url)
    try:
        upgrade_to_head(engine)
    finally:
        engine.dispose()
    print("database is at the latest schema revision")
    return 0


def _read_new_password() -> str:
    from udcs_controller.auth.schemas import MIN_PASSWORD_LENGTH

    password = os.environ.get(BOOTSTRAP_PASSWORD_ENV)
    if password is None:
        password = getpass.getpass("New admin password: ")
        if getpass.getpass("Repeat password: ") != password:
            sys.exit("passwords do not match")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    return password


def cmd_create_admin(args: argparse.Namespace) -> int:
    from udcs_controller.auth.permissions import Role
    from udcs_controller.auth.service import UsernameTaken, create_user
    from udcs_controller.database.session import create_db_engine, make_sessionmaker

    engine = create_db_engine(_settings().database_url)
    password = _read_new_password()
    with make_sessionmaker(engine)() as db:
        try:
            user = create_user(
                db,
                username=args.username,
                display_name=args.display_name or args.username,
                password=password,
                role=Role.ADMIN,
            )
        except UsernameTaken:
            sys.exit(f"user {args.username!r} already exists")
        db.commit()
        print(f"created admin {user.username} ({user.id})")
    engine.dispose()
    return 0


def cmd_create_enrollment_key(args: argparse.Namespace) -> int:
    from udcs_controller.auth.models import User
    from udcs_controller.auth.permissions import Role
    from udcs_controller.database.base import utcnow
    from udcs_controller.database.session import create_db_engine, make_sessionmaker
    from udcs_controller.nodes.service import create_enrollment_key

    settings = _settings()
    if args.ttl_minutes > settings.enrollment_key_max_ttl_minutes:
        sys.exit(f"--ttl-minutes exceeds maximum {settings.enrollment_key_max_ttl_minutes}")
    if args.max_uses > settings.enrollment_key_max_uses:
        sys.exit(f"--max-uses exceeds maximum {settings.enrollment_key_max_uses}")
    engine = create_db_engine(settings.database_url)
    with make_sessionmaker(engine)() as db:
        admin = db.scalar(select(User).where(User.username == args.created_by.lower()))
        if admin is None or admin.role != Role.ADMIN or not admin.is_active:
            sys.exit(f"{args.created_by!r} is not an active admin")
        record, key = create_enrollment_key(
            db,
            created_by=admin,
            lab=args.lab,
            ttl=timedelta(minutes=args.ttl_minutes),
            max_uses=args.max_uses,
            auto_approve=args.auto_approve,
            note=args.note,
            now=utcnow(),
        )
        db.commit()
        # The key goes to stdout only, so it can be piped; it is never logged.
        print(key)
        print(
            f"lab {record.lab!r}: up to {record.max_uses} enrollments until "
            f"{record.expires_at.isoformat()}; nodes start "
            f"{'active' if record.auto_approve else 'pending approval'}",
            file=sys.stderr,
        )
    engine.dispose()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from udcs_controller.main import create_app
    from udcs_shared.logs import configure_logging

    tls = bool(args.ssl_certfile and args.ssl_keyfile)
    if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
        sys.exit("--ssl-certfile and --ssl-keyfile must be given together")
    if not tls and not _is_loopback(args.host) and not args.insecure_allow_plaintext:
        sys.exit(
            "refusing to serve plaintext HTTP on a non-loopback address; provide "
            "--ssl-certfile/--ssl-keyfile, or pass --insecure-allow-plaintext if TLS is "
            "terminated by a trusted reverse proxy"
        )
    settings = _settings()
    configure_logging(settings.log_level, json_output=settings.log_json)
    uvicorn.run(
        create_app(settings),
        host=args.host,
        port=args.port,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
        log_config=None,
        access_log=False,  # our middleware logs requests with correlation ids
        server_header=False,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="udcs-controller", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("migrate", help="upgrade the database schema").set_defaults(func=cmd_migrate)

    p = sub.add_parser("create-admin", help="create an administrator account")
    p.add_argument("--username", required=True)
    p.add_argument("--display-name")
    p.set_defaults(func=cmd_create_admin)

    p = sub.add_parser("create-enrollment-key", help="issue a lab-scoped enrollment key")
    p.add_argument("--created-by", required=True, help="admin username to attribute it to")
    p.add_argument("--lab", required=True, help="e.g. 'CS Lab B'")
    p.add_argument("--ttl-minutes", type=int, default=24 * 60)
    p.add_argument("--max-uses", type=int, default=50)
    p.add_argument("--auto-approve", action="store_true", help="skip pending approval")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_create_enrollment_key)

    p = sub.add_parser("serve", help="run the controller API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--ssl-certfile")
    p.add_argument("--ssl-keyfile")
    p.add_argument("--insecure-allow-plaintext", action="store_true")
    p.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
