# UDCS — University Distributed Compute System

UDCS pools the CPUs and GPUs of university lab computers into one computing resource for students and researchers. Local academic use of each machine always comes first.

**Status: Milestone 1 (foundation) — see [DEVELOPMENT_STATUS.md](DEVELOPMENT_STATUS.md).** Nodes can enroll, report real hardware and stream telemetry. Job execution does not exist yet.

## Layout

| Path | What |
|---|---|
| `shared/` | `udcs-shared`: wire contracts (Pydantic) used by both sides |
| `controller/` | `udcs-controller`: FastAPI control plane (auth, node registry, audit) |
| `node_agent/` | `udcs-agent`: runs on lab PCs (hardware discovery, telemetry, heartbeats) |
| `tests/e2e/` | Real controller over TLS + real agent on real hardware |
| `docs/` | [Architecture](docs/architecture/README.md) · [Data model](docs/architecture/data-model.md) · [Agent protocol](docs/architecture/agent-protocol.md) · [API](docs/api/README.md) · [Threat model](docs/security/threat-model.md) |

## Development

Requires Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync
uv run pytest
uv run ruff check .
```

Tests use SQLite locally. Set `UDCS_TEST_DATABASE_URL=postgresql+psycopg://…` to run them against PostgreSQL, which is what CI does.

## Trying it locally

```powershell
$env:UDCS_DATABASE_URL = "sqlite:///./var/udcs.db"   # use PostgreSQL in production
uv run udcs-controller migrate
uv run udcs-controller create-admin --username itadmin
uv run udcs-controller serve --ssl-certfile server.pem --ssl-keyfile server.key
```

On a lab machine (the enrollment token is read from an environment variable or a prompt, never from the command line):

```powershell
$env:UDCS_ENROLLMENT_TOKEN = (uv run udcs-controller create-enrollment-token --created-by itadmin)
uv run udcs-agent enroll --controller-url https://controller-host:8443 --ca-bundle ca.pem
uv run udcs-agent run
uv run udcs-agent discover   # just print detected hardware
```

By default the agent stores its state in `%ProgramData%\UDCS\agent`, which needs an elevated shell. Pass `--data-dir` to use another location.
