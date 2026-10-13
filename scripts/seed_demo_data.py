"""
Demonstration Data Seeder
=========================
Seeds realistic development accounts, security policies, micro-segmented resources,
attack simulation scenarios, and baseline audit activity into SQLite.
"""

import sys
import os
import json
from datetime import datetime, timedelta

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from models import (
    db, Role, User, Resource, Policy, SimulationScenario,
    AccessRequest, TrustEvaluation, AuditLog, SecurityAlert
)

def seed_data(app=None):
    if app is None:
        app = create_app('development')

    with app.app_context():
        print("[*] Checking and seeding demonstration data...")

        # 1. Seed Roles
        roles_data = [
            ('Administrator', 'Full access to security command center, policy engine, simulation lab, and user directory.'),
            ('Manager', 'Operational manager with access to departmental HR and Finance systems within policy parameters.'),
            ('Employee', 'Standard employee role restricted to personnel records and authorized self-service tools.')
        ]
        
        role_map = {}
        for name, desc in roles_data:
            role = Role.query.filter_by(name=name).first()
            if not role:
                role = Role(name=name, description=desc, is_system=True)
                db.session.add(role)
                db.session.flush()
                print(f"  [+] Created Role: {name}")
            role_map[name] = role

        # 2. Seed Users
        users_data = [
            ('admin', 'admin@zerotrust.local', 'AdminPassword123!', 'Alex Vance', 'Cybersecurity Ops', 'Administrator'),
            ('manager', 'manager@zerotrust.local', 'ManagerPassword123!', 'Sarah Connor', 'Finance & Ops', 'Manager'),
            ('employee', 'employee@zerotrust.local', 'EmployeePassword123!', 'David Miller', 'Staff Operations', 'Employee'),
        ]

        user_map = {}
        for username, email, password, full_name, dept, role_name in users_data:
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(
                    username=username,
                    email=email,
                    full_name=full_name,
                    department=dept,
                    role_id=role_map[role_name].id,
                    is_active=True
                )
                user.set_password(password)
                db.session.add(user)
                db.session.flush()
                print(f"  [+] Created User: {username} ({role_name})")
            user_map[username] = user

        # 3. Seed Micro-Segmented Resources
        resources_data = [
            ('HR', 'Human Resources Portal', 'Corporate HR records, employee benefits, and payroll management.', 'Corporate App', 2, '10.0.1.0/24 (VLAN 10)'),
            ('FINANCE', 'Corporate Treasury & Ledger', 'High-sensitivity financial transactions, general ledger, and payment gateways.', 'Financial Database', 3, '10.0.2.0/24 (VLAN 20)'),
            ('SERVER', 'Core Production Infrastructure', 'Mission-critical server control plane, SSH bastions, and cloud container orchestration.', 'Core Infrastructure', 4, '10.0.3.0/24 (VLAN 30)'),
            ('EMPLOYEE_RECORDS', 'Staff Directory & Work Records', 'Internal personnel directory, team assignments, and public corporate contact lists.', 'Personnel Directory', 1, '10.0.4.0/24 (VLAN 40)')
        ]

        resource_map = {}
        for code, name, desc, cat, sensitivity, subnet in resources_data:
            res = Resource.query.filter_by(code=code).first()
            if not res:
                res = Resource(
                    code=code,
                    name=name,
                    description=desc,
                    category=cat,
                    sensitivity_level=sensitivity,
                    subnet_segment=subnet,
                    is_active=True
                )
                db.session.add(res)
                db.session.flush()
                print(f"  [+] Created Resource: {code} [{subnet}]")
            resource_map[code] = res

        # 4. Seed RBAC Access Policies
        # Administrator: All resources, all ops
        # Manager: HR (READ,WRITE), FINANCE (READ,WRITE - require_mfa), EMPLOYEE_RECORDS (READ)
        # Employee: HR (READ), EMPLOYEE_RECORDS (READ)
        policies_data = [
            # Admin Policies
            ('Administrator', 'HR', 'READ,WRITE,EXECUTE,ADMIN', 60.0, False, 'Full administrative access.'),
            ('Administrator', 'FINANCE', 'READ,WRITE,EXECUTE,ADMIN', 65.0, False, 'Treasury control oversight.'),
            ('Administrator', 'SERVER', 'READ,WRITE,EXECUTE,ADMIN', 80.0, True, 'Mandatory step-up MFA for server administration.'),
            ('Administrator', 'EMPLOYEE_RECORDS', 'READ,WRITE,EXECUTE,ADMIN', 60.0, False, 'Full directory management.'),
            
            # Manager Policies
            ('Manager', 'HR', 'READ,WRITE', 65.0, False, 'Departmental employee management.'),
            ('Manager', 'FINANCE', 'READ,WRITE', 75.0, True, 'Step-up MFA enforced for financial approvals.'),
            ('Manager', 'EMPLOYEE_RECORDS', 'READ', 60.0, False, 'Read-only directory access.'),
            
            # Employee Policies
            ('Employee', 'EMPLOYEE_RECORDS', 'READ', 60.0, False, 'General employee self-service directory.'),
            ('Employee', 'HR', 'READ', 65.0, False, 'Self-service benefits portal.')
        ]

        for role_name, res_code, ops, min_trust, req_mfa, notes in policies_data:
            r_id = role_map[role_name].id
            res_id = resource_map[res_code].id
            policy = Policy.query.filter_by(role_id=r_id, resource_id=res_id).first()
            if not policy:
                policy = Policy(
                    role_id=r_id,
                    resource_id=res_id,
                    allowed_operations=ops,
                    min_trust_score=min_trust,
                    require_mfa=req_mfa,
                    restriction_notes=notes,
                    is_active=True
                )
                db.session.add(policy)
                print(f"  [+] Created Policy: {role_name} -> {res_code} [{ops}]")

        # 5. Seed 10 Attack & Threat Simulation Scenarios
        scenarios_data = [
            {
                'code': 'SCENARIO-01',
                'name': 'Authorized Privileged Access',
                'category': 'Access Control',
                'objective': 'Demonstrate a legitimate administrator accessing core servers with healthy corporate posture and high trust.',
                'expected_decision': 'ALLOW',
                'test_user_role': 'Administrator',
                'test_resource_code': 'SERVER',
                'inputs': {
                    'operation': 'ADMIN',
                    'identity': 'VERIFIED_MFA',
                    'device': 'MANAGED_COMPLIANT',
                    'context': 'BUSINESS_HOURS',
                    'behaviour': 'NORMAL_FREQUENCY',
                    'resource_safety': 40.0,
                    'history': 'HIGH_COMPLIANCE',
                    'threat': 'CLEAN',
                    'is_mfa_verified': True
                }
            },
            {
                'code': 'SCENARIO-02',
                'name': 'Unauthorized Lateral Movement Attempt',
                'category': 'RBAC Violation',
                'objective': 'Demonstrate that an employee attempting to access the core Server plane is instantly blocked by RBAC regardless of trust score.',
                'expected_decision': 'BLOCK',
                'test_user_role': 'Employee',
                'test_resource_code': 'SERVER',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'VALID_SESSION',
                    'device': 'MANAGED_COMPLIANT',
                    'context': 'BUSINESS_HOURS',
                    'behaviour': 'NORMAL_FREQUENCY',
                    'resource_safety': 40.0,
                    'history': 'NORMAL',
                    'threat': 'CLEAN'
                }
            },
            {
                'code': 'SCENARIO-03',
                'name': 'Untrusted & Unhealthy Endpoint Device',
                'category': 'Device Integrity',
                'objective': 'Simulate access from a compromised/jailbroken device lacking active EDR defense.',
                'expected_decision': 'BLOCK',
                'test_user_role': 'Manager',
                'test_resource_code': 'FINANCE',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'VALID_SESSION',
                    'device': 'JAILBROKEN_OR_COMPROMISED',
                    'context': 'BUSINESS_HOURS',
                    'behaviour': 'NORMAL_FREQUENCY',
                    'resource_safety': 60.0,
                    'history': 'NORMAL',
                    'threat': 'CLEAN'
                }
            },
            {
                'code': 'SCENARIO-04',
                'name': 'Anomalous Off-Hours Request',
                'category': 'Contextual Anomaly',
                'objective': 'Simulate an unusual access request at 03:30 AM outside normal operating schedule.',
                'expected_decision': 'ADDITIONAL_VERIFICATION',
                'test_user_role': 'Manager',
                'test_resource_code': 'HR',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'VALID_SESSION',
                    'device': 'MANAGED_COMPLIANT',
                    'context': 'ANOMALOUS_OFF_HOURS',
                    'behaviour': 'NORMAL_FREQUENCY',
                    'resource_safety': 80.0,
                    'history': 'NORMAL',
                    'threat': 'CLEAN'
                }
            },
            {
                'code': 'SCENARIO-05',
                'name': 'High-Frequency Brute-Force Pattern',
                'category': 'Behavioral Risk',
                'objective': 'Simulate an automated tool making repeated rapid queries, severely degrading behavioral trust.',
                'expected_decision': 'BLOCK',
                'test_user_role': 'Employee',
                'test_resource_code': 'EMPLOYEE_RECORDS',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'VALID_SESSION',
                    'device': 'MANAGED_COMPLIANT',
                    'context': 'BUSINESS_HOURS',
                    'behaviour': 'BRUTE_FORCE_ANOMALY',
                    'resource_safety': 95.0,
                    'history': 'RECENT_DENIALS',
                    'threat': 'CLEAN'
                }
            },
            {
                'code': 'SCENARIO-06',
                'name': 'Blacklisted Threat Intelligence Source',
                'category': 'Threat Intelligence',
                'objective': 'Simulate access originating from a known Tor exit node or botnet C2 network.',
                'expected_decision': 'BLOCK',
                'test_user_role': 'Administrator',
                'test_resource_code': 'HR',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'VALID_SESSION',
                    'device': 'UNKNOWN_DEVICE',
                    'context': 'BUSINESS_HOURS',
                    'behaviour': 'NORMAL_FREQUENCY',
                    'resource_safety': 80.0,
                    'history': 'NORMAL',
                    'threat': 'KNOWN_TOR_EXIT_NODE'
                }
            },
            {
                'code': 'SCENARIO-07',
                'name': 'High-Sensitivity Treasury Step-Up Challenge',
                'category': 'Adaptive Step-Up',
                'objective': 'Demonstrate automatic step-up challenge when requesting high-sensitivity Financial records without pre-verified MFA.',
                'expected_decision': 'ADDITIONAL_VERIFICATION',
                'test_user_role': 'Manager',
                'test_resource_code': 'FINANCE',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'VALID_SESSION',
                    'device': 'RECOGNIZED_BYOD',
                    'context': 'BUSINESS_HOURS',
                    'behaviour': 'NORMAL_FREQUENCY',
                    'resource_safety': 60.0,
                    'history': 'GOOD',
                    'threat': 'CLEAN',
                    'is_mfa_verified': False
                }
            },
            {
                'code': 'SCENARIO-08',
                'name': 'Stale Identity / Session Hijacking Indicator',
                'category': 'Identity Integrity',
                'objective': 'Simulate an unverified or stale identity token indicative of cookie theft or session hijacking.',
                'expected_decision': 'BLOCK',
                'test_user_role': 'Manager',
                'test_resource_code': 'HR',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'UNVERIFIED',
                    'device': 'UNKNOWN_DEVICE',
                    'context': 'OFF_HOURS_NIGHT',
                    'behaviour': 'NORMAL_FREQUENCY',
                    'resource_safety': 80.0,
                    'history': 'WARNINGS',
                    'threat': 'SUSPICIOUS_UNCLASSIFIED'
                }
            },
            {
                'code': 'SCENARIO-09',
                'name': 'Abnormal Rapid Sequence Burst',
                'category': 'Behavioral Risk',
                'objective': 'Simulate burst automated requests to sensitive records indicating script scraping.',
                'expected_decision': 'BLOCK',
                'test_user_role': 'Employee',
                'test_resource_code': 'EMPLOYEE_RECORDS',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'VALID_SESSION',
                    'device': 'MANAGED_COMPLIANT',
                    'context': 'BUSINESS_HOURS',
                    'behaviour': 'RAPID_SEQUENCE_BURST',
                    'resource_safety': 95.0,
                    'history': 'RECENT_DENIALS',
                    'threat': 'CLEAN'
                }
            },
            {
                'code': 'SCENARIO-10',
                'name': 'Provisional Trust Multi-Factor Challenge',
                'category': 'Adaptive Verification',
                'objective': 'Simulate a roaming employee whose trust score falls directly into the provisional band (60-80).',
                'expected_decision': 'ADDITIONAL_VERIFICATION',
                'test_user_role': 'Employee',
                'test_resource_code': 'HR',
                'inputs': {
                    'operation': 'READ',
                    'identity': 'VALID_SESSION',
                    'device': 'RECOGNIZED_BYOD',
                    'context': 'DOMESTIC_REMOTE',
                    'behaviour': 'MODERATE_ELEVATION',
                    'resource_safety': 80.0,
                    'history': 'NEUTRAL',
                    'threat': 'LOW_RISK_COMMERCIAL_VPN',
                    'is_mfa_verified': False
                }
            }
        ]

        for s_data in scenarios_data:
            scenario = SimulationScenario.query.filter_by(code=s_data['code']).first()
            if not scenario:
                scenario = SimulationScenario(
                    code=s_data['code'],
                    name=s_data['name'],
                    category=s_data['category'],
                    objective=s_data['objective'],
                    expected_decision=s_data['expected_decision'],
                    test_user_role=s_data['test_user_role'],
                    test_resource_code=s_data['test_resource_code'],
                    simulated_inputs_json=json.dumps(s_data['inputs']),
                    is_builtin=True
                )
                db.session.add(scenario)
                print(f"  [+] Created Simulation Scenario: {s_data['code']} - {s_data['name']}")

        # 6. Seed Baseline Access Requests & Logs for rich initial dashboard
        if AccessRequest.query.count() == 0:
            print("  [*] Seeding baseline access requests and audit logs...")
            now = datetime.utcnow()
            
            sample_evals = [
                (user_map['admin'], resource_map['SERVER'], 'ADMIN', 'PASS', 92.5, 'ALLOW', 'Verified high trust admin session.', now - timedelta(minutes=45)),
                (user_map['manager'], resource_map['FINANCE'], 'WRITE', 'PASS', 74.0, 'ADDITIONAL_VERIFICATION', 'Provisional trust score requires step-up OTP.', now - timedelta(minutes=30)),
                (user_map['employee'], resource_map['EMPLOYEE_RECORDS'], 'READ', 'PASS', 84.0, 'ALLOW', 'Staff directory read access granted.', now - timedelta(minutes=22)),
                (user_map['employee'], resource_map['SERVER'], 'READ', 'FAIL', 71.0, 'BLOCK', 'Access Denied by RBAC: Role Employee has no active policy for SERVER.', now - timedelta(minutes=15)),
                (user_map['manager'], resource_map['HR'], 'READ', 'PASS', 82.5, 'ALLOW', 'Normal departmental access allowed.', now - timedelta(minutes=8)),
                (user_map['employee'], resource_map['FINANCE'], 'READ', 'FAIL', 55.0, 'BLOCK', 'Access Denied by RBAC: Role Employee disallowed on FINANCE.', now - timedelta(minutes=2)),
            ]

            for u, res, op, rbac_res, score, dec, reason, tstamp in sample_evals:
                req = AccessRequest(
                    user_id=u.id,
                    resource_id=res.id,
                    operation=op,
                    rbac_result=rbac_res,
                    trust_score=score,
                    decision=dec,
                    decision_reason=reason,
                    timestamp=tstamp
                )
                db.session.add(req)
                db.session.flush()

                # Trust Evaluation
                t_eval = TrustEvaluation(
                    access_request_id=req.id,
                    identity_score=90.0,
                    device_score=85.0 if score > 70 else 40.0,
                    context_score=85.0,
                    behavior_score=90.0 if score > 70 else 30.0,
                    resource_safety_score=80.0,
                    history_score=85.0,
                    threat_safety_score=100.0,
                    raw_trust_score=score,
                    final_trust_score=score,
                    timestamp=tstamp
                )
                db.session.add(t_eval)

                # Audit Log
                log_status = 'SUCCESS' if dec == 'ALLOW' else ('WARNING' if dec == 'ADDITIONAL_VERIFICATION' else 'BLOCKED')
                audit = AuditLog(
                    event_type='ACCESS_EVALUATION',
                    actor_id=u.id,
                    actor_username=u.username,
                    resource_code=res.code,
                    action=f"REQUEST_{op}",
                    status=log_status,
                    trust_score=score,
                    decision=dec,
                    reason=reason,
                    timestamp=tstamp
                )
                db.session.add(audit)

            # Security Alerts
            alert1 = SecurityAlert(
                alert_type='UNAUTHORIZED_LATERAL_MOVEMENT',
                severity='HIGH',
                title='Unauthorized Access Attempt to SERVER Subnet',
                description='Employee account david.miller attempted connection to production server segment (10.0.3.0/24). RBAC gate enforced block.',
                source_ip='10.0.4.15',
                timestamp=now - timedelta(minutes=15)
            )
            db.session.add(alert1)

        db.session.commit()
        print("[+] Demonstration data seeding complete.")

if __name__ == '__main__':
    seed_data()
