"""
Role-Based Access Control (RBAC) Engine
======================================
Enforces strict baseline authorization boundaries prior to trust evaluation.
Zero Trust Rule: Trust score CANNOT override an RBAC denial.
"""

from typing import Tuple, Optional
from models.policy import Policy
from models.role import Role
from models.resource import Resource

def evaluate_rbac(
    user_role_name: str,
    resource_code: str,
    operation: str = 'READ',
    role_id: Optional[int] = None,
    resource_id: Optional[int] = None
) -> Tuple[bool, str, Optional[Policy]]:
    """
    Evaluates whether a given role is authorized to perform an operation on a resource.
    
    Returns:
        Tuple of (is_authorized: bool, reason: str, matching_policy: Optional[Policy])
    """
    op = operation.strip().upper()
    role_name = user_role_name.strip()
    res_code = resource_code.strip().upper()

    # Query matching policy
    query = Policy.query.filter(Policy.is_active.is_(True))
    
    if role_id and resource_id:
        policy = query.filter_by(role_id=role_id, resource_id=resource_id).first()
    else:
        # Join by Role name and Resource code
        policy = (
            query.join(Role, Policy.role_id == Role.id)
            .join(Resource, Policy.resource_id == Resource.id)
            .filter(Role.name == role_name, Resource.code == res_code)
            .first()
        )

    if not policy:
        return (
            False,
            f"RBAC Policy Denial: Role '{role_name}' has no active access policy defined for resource '{res_code}'.",
            None
        )

    if not policy.allows_operation(op):
        allowed = policy.allowed_operations
        return (
            False,
            f"RBAC Operation Denial: Role '{role_name}' is authorized for [{allowed}], but requested operation '{op}' is disallowed on resource '{res_code}'.",
            policy
        )

    return (
        True,
        f"RBAC Baseline Authorization Granted: Role '{role_name}' is authorized for '{op}' on '{res_code}'.",
        policy
    )
