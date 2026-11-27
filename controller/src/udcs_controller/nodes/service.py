"""Node registry: enrollment, identity, heartbeats, inventory, admin state. Callers commit."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta

from pydantic import ValidationError
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from udcs_controller.auth.models import User
from udcs_controller.config import Settings
from udcs_controller.core import security
from udcs_controller.nodes.models import (
    EnrollmentKey,
    HardwareInventoryRecord,
    Node,
    NodeExposureAudit,
)
from udcs_controller.nodes.schemas import Connectivity, GpuModelSummary, NodeOut, ResourceSummary
from udcs_shared.agent_api import (
    ENROLLMENT_KEY_PREFIX,
    NODE_CREDENTIAL_PREFIX,
    PROTOCOL_VERSION,
    EnrollRequest,
    HeartbeatRequest,
    HeartbeatResponse,
    NodeAdminState,
)
from udcs_shared.exposure import ExposureReport, image_key, summary
from udcs_shared.hardware import HardwareInventory
from udcs_shared.protection import ProtectionPolicy
from udcs_shared.telemetry import TelemetrySnapshot

logger = logging.getLogger(__name__)


class EnrollmentRejected(Exception):
    """Key unknown, expired, revoked or exhausted. Deliberately not more specific."""


class UnsupportedProtocol(Exception):
    pass


class InvalidStateTransition(Exception):
    pass


def check_protocol(version: int) -> None:
    if version != PROTOCOL_VERSION:
        raise UnsupportedProtocol(
            f"protocol version {version} is not supported (controller speaks {PROTOCOL_VERSION})"
        )


# -- enrollment keys -------------------------------------------------------------------


def create_enrollment_key(
    db: Session,
    *,
    created_by: User | None,
    lab: str,
    ttl: timedelta,
    max_uses: int,
    auto_approve: bool,
    note: str,
    now: datetime,
) -> tuple[EnrollmentKey, str]:
    secret = security.generate_token(ENROLLMENT_KEY_PREFIX)
    record = EnrollmentKey(
        token_hash=security.hash_token(secret),
        lab=lab,
        note=note,
        created_by_user_id=created_by.id if created_by else None,
        created_at=now,
        expires_at=now + ttl,
        max_uses=max_uses,
        use_count=0,
        auto_approve=auto_approve,
    )
    db.add(record)
    db.flush()
    return record, secret


def revoke_enrollment_key(key: EnrollmentKey, *, now: datetime) -> None:
    """Stops further enrollment. Nodes already enrolled keep their own credentials."""
    if key.revoked_at is None:
        key.revoked_at = now


def enroll_node(
    db: Session, request: EnrollRequest, *, now: datetime, client_ip: str | None
) -> tuple[Node, str, EnrollmentKey]:
    check_protocol(request.protocol_version)
    if not request.enrollment_token.startswith(ENROLLMENT_KEY_PREFIX):
        raise EnrollmentRejected
    key = db.scalar(
        select(EnrollmentKey).where(
            EnrollmentKey.token_hash == security.hash_token(request.enrollment_token)
        )
    )
    if key is None:
        raise EnrollmentRejected
    # Atomic claim of one use: concurrent enrollments can never exceed max_uses.
    claimed = db.execute(
        update(EnrollmentKey)
        .where(
            EnrollmentKey.id == key.id,
            EnrollmentKey.revoked_at.is_(None),
            EnrollmentKey.expires_at > now,
            EnrollmentKey.use_count < EnrollmentKey.max_uses,
        )
        .values(use_count=EnrollmentKey.use_count + 1, last_used_at=now)
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        raise EnrollmentRejected

    credential = security.generate_token(NODE_CREDENTIAL_PREFIX)
    inventory = request.inventory
    node = Node(
        name=request.requested_name or inventory.os.hostname[:128],
        hostname=inventory.os.hostname,
        lab=key.lab,
        admin_state=NodeAdminState.ACTIVE if key.auto_approve else NodeAdminState.PENDING,
        credential_hash=security.hash_token(credential),
        credential_issued_at=now,
        enrollment_key_id=key.id,
        enrolled_at=now,
        approved_at=now if key.auto_approve else None,
        last_heartbeat_at=now,
        last_seen_ip=client_ip,
        agent_version=inventory.agent_version,
        protocol_version=request.protocol_version,
    )
    db.add(node)
    db.flush()
    store_inventory(db, node, inventory, now=now)
    return node, credential, key


# -- node identity -------------------------------------------------------------------------


def authenticate_node(db: Session, credential: str, *, now: datetime) -> tuple[Node, bool] | None:
    """Returns (node, rotated). Using a pending (rotated) credential promotes it."""
    if not credential.startswith(NODE_CREDENTIAL_PREFIX):
        return None
    digest = security.hash_token(credential)
    node = db.scalar(
        select(Node).where(
            or_(Node.credential_hash == digest, Node.pending_credential_hash == digest)
        )
    )
    if node is None:
        return None
    if node.pending_credential_hash == digest:
        node.credential_hash = digest
        node.pending_credential_hash = None
        node.credential_issued_at = now
        return node, True
    return node, False


def begin_credential_rotation(node: Node) -> str:
    """Issue a new credential; the old one stays valid until the new one is first used."""
    credential = security.generate_token(NODE_CREDENTIAL_PREFIX)
    node.pending_credential_hash = security.hash_token(credential)
    return credential


def rotation_due(node: Node, *, now: datetime, settings: Settings) -> bool:
    age = now - node.credential_issued_at
    return age >= timedelta(days=settings.node_credential_max_age_days)


def approve_node(node: Node, *, approver: User, now: datetime) -> None:
    if node.admin_state != NodeAdminState.PENDING:
        raise InvalidStateTransition(f"node is {node.admin_state.value}, not pending")
    node.admin_state = NodeAdminState.ACTIVE
    node.approved_at = now
    node.approved_by_user_id = approver.id


def store_inventory(
    db: Session, node: Node, inventory: HardwareInventory, *, now: datetime
) -> bool:
    """Persist inventory; returns True if it differed from what was stored."""
    fingerprint = inventory.fingerprint()  # computed here, never trusted from the agent
    changed = node.inventory_fingerprint != fingerprint
    values = {
        "fingerprint": fingerprint,
        "inventory": inventory.model_dump(mode="json"),
        "logical_cores": inventory.cpu.logical_cores,
        "memory_total_bytes": inventory.memory.total_bytes,
        "gpu_count": len(inventory.gpus),
        "gpu_memory_total_bytes": sum(g.memory_total_bytes or 0 for g in inventory.gpus),
        "updated_at": now,
    }
    if node.inventory is None:
        node.inventory = HardwareInventoryRecord(node_id=node.id, **values)
    else:
        for key, value in values.items():
            setattr(node.inventory, key, value)
    node.inventory_fingerprint = fingerprint
    node.hostname = inventory.os.hostname
    node.agent_version = inventory.agent_version
    return changed


def protection_policy(settings: Settings) -> ProtectionPolicy:
    """Fleet-wide policy. The agent merges it with its local floor; the stricter wins."""
    return ProtectionPolicy(version=settings.protection_policy_version)


def record_heartbeat(
    db: Session,
    node: Node,
    heartbeat: HeartbeatRequest,
    *,
    now: datetime,
    client_ip: str | None,
    settings: Settings,
) -> HeartbeatResponse:
    check_protocol(heartbeat.protocol_version)
    node.last_heartbeat_at = now  # controller clock: agent clocks are untrusted
    node.last_seen_ip = client_ip
    node.protocol_version = heartbeat.protocol_version
    node.latest_telemetry = heartbeat.telemetry.model_dump(mode="json")
    return HeartbeatResponse(
        heartbeat_interval_seconds=settings.heartbeat_interval_seconds,
        inventory_required=node.inventory_fingerprint != heartbeat.inventory_fingerprint,
        admin_state=node.admin_state,
        protection_policy=protection_policy(settings),
        rotate_credential=rotation_due(node, now=now, settings=settings),
    )


def connectivity(node: Node, *, now: datetime, settings: Settings) -> Connectivity:
    if node.admin_state == NodeAdminState.REVOKED or node.last_heartbeat_at is None:
        return Connectivity.OFFLINE
    if now - node.last_heartbeat_at < settings.offline_after:
        return Connectivity.ONLINE
    return Connectivity.OFFLINE


def set_admin_state(node: Node, state: NodeAdminState) -> None:
    if node.admin_state == NodeAdminState.REVOKED:
        raise InvalidStateTransition("a revoked node cannot be reactivated; re-enroll it")
    if node.admin_state == NodeAdminState.PENDING:
        raise InvalidStateTransition("approve the node first")
    if state in (NodeAdminState.REVOKED, NodeAdminState.PENDING):
        raise InvalidStateTransition(f"cannot set {state.value} here")
    node.admin_state = state


def revoke_node(node: Node, *, now: datetime) -> None:
    node.admin_state = NodeAdminState.REVOKED
    node.revoked_at = now
    node.pending_credential_hash = None


def _parse_or_none(model: type[HardwareInventory] | type[TelemetrySnapshot], data: object):
    """Stored JSON may predate a schema change; degrade to None rather than 500."""
    if data is None:
        return None
    try:
        return model.model_validate(data)
    except ValidationError:
        logger.warning("stored %s no longer validates", model.__name__)
        return None


def to_out(node: Node, *, now: datetime, settings: Settings) -> NodeOut:
    conn = connectivity(node, now=now, settings=settings)
    return NodeOut(
        id=node.id,
        name=node.name,
        hostname=node.hostname,
        lab=node.lab,
        admin_state=node.admin_state,
        connectivity=conn,
        schedulable=conn == Connectivity.ONLINE and node.admin_state == NodeAdminState.ACTIVE,
        enrolled_at=node.enrolled_at,
        approved_at=node.approved_at,
        revoked_at=node.revoked_at,
        credential_issued_at=node.credential_issued_at,
        credential_rotation_pending=node.pending_credential_hash is not None,
        last_heartbeat_at=node.last_heartbeat_at,
        last_seen_ip=node.last_seen_ip,
        agent_version=node.agent_version,
        protocol_version=node.protocol_version,
        inventory=_parse_or_none(HardwareInventory, node.inventory.inventory)
        if node.inventory
        else None,
        inventory_updated_at=node.inventory.updated_at if node.inventory else None,
        latest_telemetry=_parse_or_none(TelemetrySnapshot, node.latest_telemetry),
        user_code_allowed=node.user_code_allowed,
        user_code_ready=node.user_code_allowed and _verified_appcontainer(node),
        user_code_image=node.user_code_image,
        user_code_granted_at=node.user_code_granted_at,
        user_code_blocked=user_code_unfit(node, settings) if node.user_code_allowed else None,
    )


def resource_summary(db: Session, *, now: datetime, settings: Settings) -> ResourceSummary:
    """Aggregate capacity for students/researchers; reveals no node identities."""
    excluded = [NodeAdminState.REVOKED, NodeAdminState.PENDING]
    nodes = db.scalars(select(Node).where(Node.admin_state.not_in(excluded))).all()
    pending = (
        db.scalar(
            select(func.count()).select_from(Node).where(Node.admin_state == NodeAdminState.PENDING)
        )
        or 0
    )
    online = offline = maintenance = 0
    cores = memory = available = gpu_count = gpu_memory = 0
    models: Counter[tuple[str, int | None, str | None]] = Counter()
    for node in nodes:
        if node.admin_state == NodeAdminState.MAINTENANCE:
            maintenance += 1
            continue
        if connectivity(node, now=now, settings=settings) != Connectivity.ONLINE:
            offline += 1
            continue
        online += 1
        record = node.inventory
        if record is not None:
            cores += record.logical_cores
            memory += record.memory_total_bytes
            gpu_count += record.gpu_count
            gpu_memory += record.gpu_memory_total_bytes
            for gpu in record.inventory.get("gpus", []):
                models[
                    (gpu["name"], gpu.get("memory_total_bytes"), gpu.get("compute_capability"))
                ] += 1
        telemetry = node.latest_telemetry or {}
        available += int(telemetry.get("memory_available_bytes", 0))
    return ResourceSummary(
        generated_at=now,
        online_nodes=online,
        offline_nodes=offline,
        maintenance_nodes=maintenance,
        pending_nodes=pending,
        total_logical_cores=cores,
        total_memory_bytes=memory,
        available_memory_bytes=available,
        gpu_count=gpu_count,
        gpu_memory_total_bytes=gpu_memory,
        gpu_models=[
            GpuModelSummary(name=n, memory_total_bytes=m, compute_capability=c, count=k)
            for (n, m, c), k in sorted(models.items(), key=lambda item: (-item[1], item[0][0]))
        ],
    )


def _verified_appcontainer(node: Node) -> bool:
    from udcs_controller.jobs.service import node_verified_appcontainer

    return node_verified_appcontainer(node)


# -- user-code eligibility (ADR 0003 operator procedure) -------------------------------------


class EligibilityRefused(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def node_image(node: Node) -> str | None:
    """The OS image a node currently reports: what eligibility is bound to."""
    if node.inventory is None:
        return None
    os_info = node.inventory.inventory.get("os") or {}
    if not os_info.get("release") or not os_info.get("version"):
        return None
    return image_key(os_info["release"], os_info["version"])


def user_code_unfit(node: Node, settings: Settings) -> str | None:
    """Why this node may not run user code *right now*, or None. One rule, used by the
    scheduler, the job sync and every node package endpoint, so revoking eligibility,
    losing a capability or switching the controller flag off stops work everywhere."""
    from udcs_controller.jobs.service import node_verified_appcontainer

    if not settings.user_code_enabled:
        return "user code execution is disabled on this deployment"
    if node.admin_state != NodeAdminState.ACTIVE:
        return f"node is {node.admin_state.value}"
    if not node.user_code_allowed:
        return "node not eligible for user code (administrator setting)"
    if not node_verified_appcontainer(node):
        return "node no longer reports a verified AppContainer"
    if node.user_code_image is None or node.user_code_image != node_image(node):
        return "node image differs from the audited one"
    return None


def record_exposure_audit(
    db: Session, node: Node, report: ExposureReport, *, by: User, now: datetime
) -> NodeExposureAudit:
    """Store an exposure report for a node, re-judged here (the uploader's verdict is
    never trusted). The report must come from this node's host."""
    import hashlib

    if node.inventory is None:
        raise EligibilityRefused(409, "the node has not reported an inventory yet")
    if report.hostname.lower() != (node.hostname or "").lower():
        raise EligibilityRefused(
            422, f"the report is from host {report.hostname!r}, not {node.hostname!r}"
        )
    generated = report.generated_at
    if generated.tzinfo is None:
        from datetime import UTC

        generated = generated.replace(tzinfo=UTC)
    if generated > now + timedelta(minutes=10):
        # A future date would pass the age check forever.
        raise EligibilityRefused(422, "the report is dated in the future; check the node's clock")
    result = summary(report)
    canonical = report.model_dump_json().encode()
    record = NodeExposureAudit(
        node_id=node.id,
        sha256=hashlib.sha256(canonical).hexdigest(),
        image=report.image(),
        runner=report.runner[:64],
        passed=result["passed"],
        summary=result,
        report=report.model_dump(mode="json"),
        generated_at=report.generated_at,
        uploaded_at=now,
        uploaded_by_user_id=by.id,
    )
    db.add(record)
    db.flush()
    return record


def grant_user_code(
    db: Session, node: Node, *, by: User, now: datetime, settings: Settings
) -> NodeExposureAudit:
    """Make a node eligible. Preconditions (each refused with a reason):
    ACTIVE; a verified AppContainer in its inventory; and a passing exposure audit of
    its *current* image, taken by a SYSTEM-context run, no older than the configured
    maximum. Eligibility is then bound to that image and audit."""
    from udcs_controller.jobs.service import node_verified_appcontainer

    if node.admin_state != NodeAdminState.ACTIVE:
        raise EligibilityRefused(409, f"node is {node.admin_state.value}; only ACTIVE nodes")
    image = node_image(node)
    if image is None:
        raise EligibilityRefused(409, "the node has not reported its OS image")
    if not node_verified_appcontainer(node):
        raise EligibilityRefused(409, "the node does not report a verified AppContainer")
    audit = db.scalars(
        select(NodeExposureAudit)
        .where(NodeExposureAudit.node_id == node.id)
        .order_by(NodeExposureAudit.uploaded_at.desc())
        .limit(1)
    ).first()
    if audit is None:
        raise EligibilityRefused(409, "no exposure audit has been recorded for this node")
    if not audit.passed:
        raise EligibilityRefused(409, "the latest exposure audit has violations")
    if audit.image != image:
        raise EligibilityRefused(
            409, f"the latest audit is of image {audit.image}, node runs {image}"
        )
    if "SYSTEM" not in audit.runner.upper():
        raise EligibilityRefused(409, "the audit must be run as SYSTEM (the service context)")
    generated = audit.generated_at
    if generated.tzinfo is None:
        from datetime import UTC

        generated = generated.replace(tzinfo=UTC)
    if now - generated > timedelta(days=settings.exposure_audit_max_age_days):
        raise EligibilityRefused(409, "the latest exposure audit is too old; run it again")
    node.user_code_allowed = True
    node.user_code_image = image
    node.user_code_audit_id = audit.id
    node.user_code_granted_at = now
    node.user_code_granted_by_user_id = by.id
    return audit


def revoke_user_code(node: Node) -> None:
    """Always allowed, in any state. Takes effect at the node's next sync: package jobs
    on it are requeued and the node is told to cancel them."""
    node.user_code_allowed = False


def suspend_if_image_changed(node: Node) -> bool:
    """After an inventory update: a different OS image than the audited one suspends
    eligibility (a reimaged lab PC must be audited again). True if suspended."""
    if node.user_code_allowed and node.user_code_image != node_image(node):
        node.user_code_allowed = False
        return True
    return False
