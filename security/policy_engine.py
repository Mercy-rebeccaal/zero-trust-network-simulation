"""
Adaptive Resource Policy Engine
==============================
Applies resource-specific security criteria, including mandatory MFA,
minimum required policy trust thresholds, and operation restrictions.
"""

from typing import Tuple, Dict, Any, Optional
from models.policy import Policy
from models.resource import Resource

def evaluate_resource_policy(
    policy: Optional[Policy],
    resource: Optional[Resource],
    trust_score: float,
    operation: str,
    is_mfa_verified: bool = False
) -> Dict[str, Any]:
    """
    Evaluates policy-specific rules on top of the calculated trust score.
    
    Returns:
        Dict containing:
            - is_policy_compliant: bool
            - requires_mfa: bool
            - is_restricted: bool
            - restriction_type: Optional[str]
            - notes: str
    """
    op = operation.strip().upper()
    notes = []
    requires_mfa = False
    is_restricted = False
    restriction_type = None

    if not policy or not resource:
        return {
            'is_policy_compliant': True,
            'requires_mfa': False,
            'is_restricted': False,
            'restriction_type': None,
            'notes': 'Default policy evaluation applied.'
        }

    # 1. Check custom minimum trust threshold configured on policy
    if trust_score < policy.min_trust_score:
        return {
            'is_policy_compliant': False,
            'requires_mfa': False,
            'is_restricted': False,
            'restriction_type': 'INSUFFICIENT_TRUST',
            'notes': f"Trust score ({trust_score:.2f}) is below policy threshold ({policy.min_trust_score:.2f}) required for resource '{resource.code}'."
        }

    # 2. Check if policy or resource sensitivity mandates MFA
    if (policy.require_mfa or resource.sensitivity_level >= 4 or op == 'ADMIN') and not is_mfa_verified:
        requires_mfa = True
        notes.append(f"MFA step-up verification is mandatory for {resource.name} ({op}).")

    # 3. Check operation restriction for provisional trust (60.0 to 80.0)
    if 60.0 <= trust_score <= 80.0:
        if op in ('WRITE', 'EXECUTE', 'ADMIN'):
            is_restricted = True
            restriction_type = 'DOWNGRADED_TO_READ_ONLY'
            notes.append(f"Trust score in provisional band ({trust_score:.2f}); operation '{op}' restricted to READ-only.")
        elif not is_mfa_verified:
            requires_mfa = True
            notes.append(f"Adaptive Trust band ({trust_score:.2f}) triggers secondary verification challenge.")

    return {
        'is_policy_compliant': True,
        'requires_mfa': requires_mfa,
        'is_restricted': is_restricted,
        'restriction_type': restriction_type,
        'notes': " ".join(notes) if notes else "All resource-specific policy criteria satisfied."
    }
