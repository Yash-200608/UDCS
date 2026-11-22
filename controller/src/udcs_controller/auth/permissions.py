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
    SUBMIT_JOBS = "submit_jobs"  # submit / view / cancel *own* jobs
    MANAGE_JOBS = "manage_jobs"  # view / cancel anyone's jobs, see node placement


# Student and researcher are still identical; they will diverge on quotas and scheduling
# priority. Only catalog workloads can be submitted, so submitting runs no user code.
_USER = frozenset({Permission.VIEW_RESOURCE_SUMMARY, Permission.SUBMIT_JOBS})
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.STUDENT: _USER,
    Role.RESEARCHER: _USER,
    Role.ADMIN: frozenset(Permission),
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]
