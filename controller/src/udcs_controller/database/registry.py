"""Import every model module so `Base.metadata` is complete (Alembic, tests)."""

from udcs_controller.audit import models as audit_models
from udcs_controller.auth import models as auth_models
from udcs_controller.jobs import models as job_models
from udcs_controller.nodes import models as node_models
from udcs_controller.packages import models as package_models

__all__ = ["audit_models", "auth_models", "job_models", "node_models", "package_models"]
