"""Roles and permissions, defined in code (decision D8)."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    STUDENT = "student"
    RESEARCHER = "researcher"
    ADMIN = "admin"


class Permission(StrEnum):
    VIEW_RESOURCE_SUMMARY = "view_resource_summary"
    MANAGE_USERS = "manage_users"
    VIEW_NODES = "view_nodes"
    MANAGE_NODES = "manage_nodes"
    MANAGE_ENROLLMENT = "manage_enrollment"
    VIEW_AUDIT = "view_audit"


# Student and researcher are identical in M1; they will diverge on job quotas and
# scheduling priority (M2/M3). Keeping them distinct now avoids a data migration.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.STUDENT: frozenset({Permission.VIEW_RESOURCE_SUMMARY}),
    Role.RESEARCHER: frozenset({Permission.VIEW_RESOURCE_SUMMARY}),
    Role.ADMIN: frozenset(Permission),
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]
