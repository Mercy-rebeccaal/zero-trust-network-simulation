"""
Intelligent Adaptive Continuous Trust Engine (IACTE)
=====================================================
Evaluates 7 distinct contextual security factors to compute a continuous,
explainable Trust Score between 0.0 and 100.0 according to the Zero Trust
philosophy: 'NEVER TRUST. ALWAYS VERIFY.'
"""

from typing import Dict, Any, Union, Tuple

# Official IACTE Factor Weights (Sum = 1.00)
IACTE_WEIGHTS = {
    'identity': 0.20,
    'device': 0.15,
    'context': 0.15,
    'behaviour': 0.15,
    'resource_safety': 0.10,
    'historical_trust': 0.15,
    'threat_safety': 0.10
}

# Qualitative input mapping dictionaries
DEVICE_STATE_MAP = {
    'MANAGED_COMPLIANT': 95.0,
    'MANAGED_NON_COMPLIANT': 55.0,
    'RECOGNIZED_BYOD': 75.0,
    'UNKNOWN_DEVICE': 40.0,
    'UNHEALTHY_DEVICE': 15.0,
    'JAILBROKEN_OR_COMPROMISED': 0.0
}

CONTEXT_TIME_MAP = {
    'BUSINESS_HOURS': 95.0,
    'EXTENDED_HOURS': 80.0,
    'OFF_HOURS_EVENING': 60.0,
    'OFF_HOURS_NIGHT': 35.0,
    'ANOMALOUS_OFF_HOURS': 20.0
}

CONTEXT_LOCATION_MAP = {
    'CORP_HQ': 100.0,
    'BRANCH_OFFICE': 90.0,
    'AUTHORIZED_VPN': 85.0,
    'DOMESTIC_REMOTE': 70.0,
    'INTERNATIONAL_ROAMING': 45.0,
    'ANOMALOUS_GEO_TRAVEL': 10.0
}

BEHAVIOUR_MAP = {
    'NORMAL_FREQUENCY': 95.0,
    'MODERATE_ELEVATION': 75.0,
    'UNUSUAL_ACCESS_PATTERN': 50.0,
    'REPEATED_FAILED_REQUESTS': 25.0,
    'RAPID_SEQUENCE_BURST': 10.0,
    'BRUTE_FORCE_ANOMALY': 0.0
}

THREAT_INTEL_MAP = {
    'CLEAN': 100.0,
    'LOW_RISK_COMMERCIAL_VPN': 75.0,
    'SUSPICIOUS_UNCLASSIFIED': 35.0,
    'KNOWN_TOR_EXIT_NODE': 10.0,
    'KNOWN_BOTNET_OR_MALICIOUS': 0.0
}

RESOURCE_SENSITIVITY_SAFETY_MAP = {
    1: 95.0,  # Low sensitivity -> Inherent safety score 95%
    2: 80.0,  # Medium sensitivity -> Inherent safety score 80%
    3: 60.0,  # High sensitivity -> Inherent safety score 60%
    4: 40.0,  # Critical sensitivity -> Inherent safety score 40%
    'LOW': 95.0,
    'MEDIUM': 80.0,
    'HIGH': 60.0,
    'CRITICAL': 40.0
}

def clamp(val: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """Clamps a floating point number within [min_val, max_val]."""
    return max(min_val, min(max_val, float(val)))

def normalize_factor_value(value: Union[int, float, str], factor_name: str) -> float:
    """
    Normalizes any factor input (numeric or qualitative string token)
    into a standardized float in the range [0.0, 100.0].
    """
    if isinstance(value, (int, float)):
        return clamp(float(value))

    if isinstance(value, str):
        val_upper = value.strip().upper()
        
        # Check if it's a numeric string
        try:
            return clamp(float(val_upper))
        except ValueError:
            pass

        if factor_name == 'device':
            return DEVICE_STATE_MAP.get(val_upper, 50.0)
        elif factor_name == 'context':
            # Support combined tokens or individual time/location
            if val_upper in CONTEXT_TIME_MAP:
                return CONTEXT_TIME_MAP[val_upper]
            if val_upper in CONTEXT_LOCATION_MAP:
                return CONTEXT_LOCATION_MAP[val_upper]
            return 60.0
        elif factor_name == 'behaviour':
            return BEHAVIOUR_MAP.get(val_upper, 60.0)
        elif factor_name == 'threat_safety':
            return THREAT_INTEL_MAP.get(val_upper, 50.0)
        elif factor_name == 'resource_safety':
            return RESOURCE_SENSITIVITY_SAFETY_MAP.get(val_upper, 70.0)
        elif factor_name == 'identity':
            if val_upper in ('VERIFIED_MFA', 'STEP_UP_VERIFIED'):
                return 100.0
            elif val_upper in ('VALID_SESSION', 'ACTIVE'):
                return 90.0
            elif val_upper in ('PROVISIONAL', 'PASSWORD_RESET'):
                return 60.0
            elif val_upper in ('UNVERIFIED', 'STALE'):
                return 30.0
            return 50.0
        elif factor_name == 'historical_trust':
            if val_upper in ('EXCELLENT', 'HIGH_COMPLIANCE'):
                return 95.0
            elif val_upper in ('GOOD', 'NORMAL'):
                return 80.0
            elif val_upper in ('NEUTRAL', 'NEW_USER'):
                return 70.0
            elif val_upper in ('WARNINGS', 'RECENT_DENIALS'):
                return 40.0
            elif val_upper in ('POOR', 'FREQUENT_VIOLATIONS'):
                return 15.0
            return 70.0

    return 50.0

def calculate_iacte_trust_score(
    identity: Union[int, float, str] = 90.0,
    device: Union[int, float, str] = 95.0,
    context: Union[int, float, str] = 90.0,
    behaviour: Union[int, float, str] = 90.0,
    resource_safety: Union[int, float, str] = 80.0,
    historical_trust: Union[int, float, str] = 85.0,
    threat_safety: Union[int, float, str] = 100.0
) -> Dict[str, Any]:
    """
    Computes the authoritative IACTE continuous trust score.
    
    Formula:
        Trust Score = (Identity * 0.20) + (Device * 0.15) + (Context * 0.15)
                    + (Behaviour * 0.15) + (Resource Safety * 0.10)
                    + (Historical Trust * 0.15) + (Threat Safety * 0.10)
                    
    Returns:
        dict containing:
            - score (float): exact unrounded calculation (0.0 to 100.0)
            - rounded_score (float): rounded to 2 decimal places
            - factor_scores (dict): normalized 0-100 scores for each factor
            - contributions (dict): actual weighted contribution points for each factor
            - weights (dict): configured weights used
            - explanation (str): concise narrative explanation of factor performance
    """
    # 1. Normalize all inputs
    norm_identity = normalize_factor_value(identity, 'identity')
    norm_device = normalize_factor_value(device, 'device')
    norm_context = normalize_factor_value(context, 'context')
    norm_behaviour = normalize_factor_value(behaviour, 'behaviour')
    norm_resource_safety = normalize_factor_value(resource_safety, 'resource_safety')
    norm_historical_trust = normalize_factor_value(historical_trust, 'historical_trust')
    norm_threat_safety = normalize_factor_value(threat_safety, 'threat_safety')

    # 2. Compute individual contributions
    c_identity = norm_identity * IACTE_WEIGHTS['identity']
    c_device = norm_device * IACTE_WEIGHTS['device']
    c_context = norm_context * IACTE_WEIGHTS['context']
    c_behaviour = norm_behaviour * IACTE_WEIGHTS['behaviour']
    c_res_safety = norm_resource_safety * IACTE_WEIGHTS['resource_safety']
    c_history = norm_historical_trust * IACTE_WEIGHTS['historical_trust']
    c_threat_safety = norm_threat_safety * IACTE_WEIGHTS['threat_safety']

    # 3. Sum total trust score
    raw_score = (
        c_identity +
        c_device +
        c_context +
        c_behaviour +
        c_res_safety +
        c_history +
        c_threat_safety
    )

    # 4. Strict clamping between 0.0 and 100.0
    final_score = clamp(raw_score, 0.0, 100.0)
    rounded_score = round(final_score, 2)

    # 5. Build human-readable explanation
    weakest_factors = []
    strongest_factors = []

    factor_map = {
        'Identity Confidence': norm_identity,
        'Device Integrity': norm_device,
        'Contextual Posture': norm_context,
        'Behavioral Baseline': norm_behaviour,
        'Resource Sensitivity Safety': norm_resource_safety,
        'Historical Trust History': norm_historical_trust,
        'Threat Intelligence Safety': norm_threat_safety
    }

    for name, val in factor_map.items():
        if val < 60.0:
            weakest_factors.append(f"{name} ({val:.1f}/100)")
        elif val >= 85.0:
            strongest_factors.append(f"{name} ({val:.1f}/100)")

    explanation_parts = []
    if rounded_score > 80.0:
        explanation_parts.append(f"Trust score is high ({rounded_score:.2f}/100). Confidence profile is robust across primary indicators.")
    elif rounded_score >= 60.0:
        explanation_parts.append(f"Trust score is moderate ({rounded_score:.2f}/100). Falls within adaptive verification zone.")
    else:
        explanation_parts.append(f"Trust score is critically degraded ({rounded_score:.2f}/100). Falls below safety baseline (60.00).")

    if weakest_factors:
        explanation_parts.append(f"Risk indicators identified in: {', '.join(weakest_factors)}.")
    if strongest_factors and rounded_score >= 60.0:
        explanation_parts.append(f"Strong trust pillars: {', '.join(strongest_factors[:2])}.")

    explanation = " ".join(explanation_parts)

    return {
        'score': final_score,
        'rounded_score': rounded_score,
        'factor_scores': {
            'identity': norm_identity,
            'device': norm_device,
            'context': norm_context,
            'behaviour': norm_behaviour,
            'resource_safety': norm_resource_safety,
            'historical_trust': norm_historical_trust,
            'threat_safety': norm_threat_safety
        },
        'contributions': {
            'identity': round(c_identity, 2),
            'device': round(c_device, 2),
            'context': round(c_context, 2),
            'behaviour': round(c_behaviour, 2),
            'resource_safety': round(c_res_safety, 2),
            'historical_trust': round(c_history, 2),
            'threat_safety': round(c_threat_safety, 2)
        },
        'weights': IACTE_WEIGHTS,
        'explanation': explanation
    }
