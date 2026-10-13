"""
Intelligent Adaptive Continuous Trust Engine (IACTE) Formula & Weights Tests
"""

import pytest
from security.iacte import calculate_iacte_trust_score, normalize_factor_value, IACTE_WEIGHTS

def test_iacte_weights_sum_to_one():
    total_weight = sum(IACTE_WEIGHTS.values())
    assert abs(total_weight - 1.00) < 1e-9

def test_maximum_trust_score():
    res = calculate_iacte_trust_score(
        identity=100.0,
        device=100.0,
        context=100.0,
        behaviour=100.0,
        resource_safety=100.0,
        historical_trust=100.0,
        threat_safety=100.0
    )
    assert res['score'] == 100.0
    assert res['rounded_score'] == 100.0

def test_minimum_trust_score():
    res = calculate_iacte_trust_score(
        identity=0.0,
        device=0.0,
        context=0.0,
        behaviour=0.0,
        resource_safety=0.0,
        historical_trust=0.0,
        threat_safety=0.0
    )
    assert res['score'] == 0.0
    assert res['rounded_score'] == 0.0

def test_weighted_contributions():
    # Identity: 100 * 0.20 = 20.0
    # Device: 80 * 0.15 = 12.0
    # Context: 60 * 0.15 = 9.0
    # Behaviour: 70 * 0.15 = 10.5
    # Resource Safety: 50 * 0.10 = 5.0
    # Historical Trust: 90 * 0.15 = 13.5
    # Threat Safety: 100 * 0.10 = 10.0
    # Total = 20.0 + 12.0 + 9.0 + 10.5 + 5.0 + 13.5 + 10.0 = 80.0
    res = calculate_iacte_trust_score(
        identity=100.0,
        device=80.0,
        context=60.0,
        behaviour=70.0,
        resource_safety=50.0,
        historical_trust=90.0,
        threat_safety=100.0
    )
    assert abs(res['score'] - 80.0) < 1e-5
    assert res['contributions']['identity'] == 20.0
    assert res['contributions']['device'] == 12.0
    assert res['contributions']['context'] == 9.0
    assert res['contributions']['behaviour'] == 10.5
    assert res['contributions']['resource_safety'] == 5.0
    assert res['contributions']['historical_trust'] == 13.5
    assert res['contributions']['threat_safety'] == 10.0

def test_score_clamping():
    # Values above 100 or below 0 should clamp safely
    res = calculate_iacte_trust_score(
        identity=150.0,
        device=-20.0,
        context=200.0,
        behaviour=50.0,
        resource_safety=50.0,
        historical_trust=50.0,
        threat_safety=50.0
    )
    assert 0.0 <= res['score'] <= 100.0

def test_qualitative_token_normalization():
    assert normalize_factor_value('MANAGED_COMPLIANT', 'device') == 95.0
    assert normalize_factor_value('JAILBROKEN_OR_COMPROMISED', 'device') == 0.0
    assert normalize_factor_value('CLEAN', 'threat_safety') == 100.0
    assert normalize_factor_value('KNOWN_TOR_EXIT_NODE', 'threat_safety') == 10.0
    assert normalize_factor_value('BUSINESS_HOURS', 'context') == 95.0
