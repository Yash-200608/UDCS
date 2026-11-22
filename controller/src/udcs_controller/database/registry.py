"""Import every model module so `Base.metadata` is complete (Alembic, tests)."""

from udcs_controller.audit import models as audit_models
from udcs_controller.auth import models as auth_models
from udcs_controller.nodes import models as node_models

__all__ = ["audit_models", "auth_models", "node_models"]
