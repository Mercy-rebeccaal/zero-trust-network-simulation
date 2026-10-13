# ZERO//TRUST — Intelligent Security Command Center
### Zero Trust Network Simulation Platform Supported by Intelligent Adaptive Continuous Trust Engine (IACTE)

> **Core Axiom:** *“NEVER TRUST. ALWAYS VERIFY.”*

---

## 1. Project Overview & Role

**ZERO//TRUST** is a comprehensive, enterprise-grade cybersecurity web application and research-oriented network simulation platform. Designed as a final-year engineering capstone project, it demonstrates the implementation of Zero Trust Architecture (ZTA) principles compliant with NIST SP 800-207 guidelines.

Rather than relying on outdated perimeter defenses (VPNs, firewalls with implicit trust), ZERO//TRUST evaluates **every single access request** across seven contextual security dimensions, enforces server-side Role-Based Access Control (RBAC), calculates dynamic continuous trust scores, and isolates corporate assets within micro-segmented subnets.

---

## 2. Architectural Design & The IACTE Engine

The platform implements a multi-gate verification pipeline:

```
[ Requesting Subject / Identity ]
               │
               ▼
   [ Authentication Gateway ] ── (Session integrity, anti-fixation, CSRF tokens)
               │
               ▼
      [ RBAC Policy Gate ]    ── (Gate 1: Strict least-privilege role permissions)
               │                  * If RBAC fails ──> UNCONDITIONAL BLOCK
               ▼
      [  IACTE Engine  ]      ── (Gate 2: 7-factor continuous weighted calculation)
               │
               ▼
   [ Adaptive Decision Matrix ]── (Gate 3: Threshold boundaries & step-up challenges)
               │
               ├──> ALLOW (> 80.00) ───────────────┐
               ├──> ADDITIONAL_VERIFICATION (60-80) │
               ├──> RESTRICT (Provisional read-only)│
               └──> BLOCK (< 60.00)                │
                                                   ▼
               [ Micro-Segmented Enclaves: HR | FINANCE | SERVER | RECORDS ]
                                                   │
                                                   ▼
               [ Immutable Audit Trail & SIEM Collector (SQLite) ]
```

### The 7 IACTE Security Factors & Mathematical Formula

Each factor is normalized to a standard numeric range of **0.0 to 100.0**. The weights are mathematically calibrated to sum to exactly **1.00**:

| Factor | Name | Weight | Evaluation Criteria |
| :--- | :--- | :---: | :--- |
| **Factor 1** | **Identity Confidence** | `0.20` | Session validity, MFA verification state, password freshness |
| **Factor 2** | **Device Integrity** | `0.15` | Managed EDR compliance, disk encryption, BYOD vs jailbroken |
| **Factor 3** | **Contextual Posture** | `0.15` | Access time (business vs midnight) and geographic location |
| **Factor 4** | **Behavioral Consistency** | `0.15` | Request rate, sequence bursts, automated brute-force anomalies |
| **Factor 5** | **Resource Sensitivity Safety** | `0.10` | Inherent risk normalization (Critical Server=40%, Low Directory=95%) |
| **Factor 6** | **Historical Compliance** | `0.15` | Ratio of past allowed requests vs recent denial history |
| **Factor 7** | **Threat Intelligence Safety** | `0.10` | IP reputation, commercial VPN vs known Tor exit node/botnet |

#### Formula:
$$\text{Trust Score} = (\text{Identity} \times 0.20) + (\text{Device} \times 0.15) + (\text{Context} \times 0.15) + (\text{Behaviour} \times 0.15) + (\text{Resource Safety} \times 0.10) + (\text{History} \times 0.15) + (\text{Threat Safety} \times 0.10)$$

*Bounds:* Clamped strictly between `0.0` and `100.0`. Displayed rounded to 2 decimal places.

### Deterministic Threshold Decision Boundaries

- **Score > 80.00:** `ALLOW` (Provided RBAC and mandatory resource policies pass)
- **60.00 ≤ Score ≤ 80.00:** `ADDITIONAL_VERIFICATION` (MFA OTP Challenge) or `RESTRICT` (Read-only mode)
- **Score < 60.00:** `BLOCK`

#### Exact Boundary Edge Cases:
- **`59.99`** $\rightarrow$ `BLOCK`
- **`60.00`** $\rightarrow$ `ADDITIONAL_VERIFICATION`
- **`80.00`** $\rightarrow$ `ADDITIONAL_VERIFICATION`
- **`80.01`** $\rightarrow$ `ALLOW`

> **Critical Rule:** A high trust score **never** overrides an RBAC denial. If an Employee attempts to access the core Server infrastructure, the decision is **BLOCK** immediately regardless of a 100.0 trust score.

---

## 3. Micro-Segmented Resource Enclaves

| Code | Resource Name | Sensitivity | Subnet / VLAN Segment |
| :--- | :--- | :---: | :--- |
| `HR` | Human Resources Portal | Medium (Level 2) | `10.0.1.0/24 (VLAN 10)` |
| `FINANCE` | Corporate Treasury & Ledger | High (Level 3) | `10.0.2.0/24 (VLAN 20)` |
| `SERVER` | Core Production Infrastructure | Critical (Level 4) | `10.0.3.0/24 (VLAN 30)` |
| `EMPLOYEE_RECORDS` | Staff Directory & Work Records | Low (Level 1) | `10.0.4.0/24 (VLAN 40)` |

Lateral movement between subnets is strictly blocked by default. Access to HR does not permit transverse access to Finance or Servers.

---

## 4. Attack and Threat Simulation Lab (10 Scenarios)

1. **SCENARIO-01: Authorized Privileged Access** &mdash; Administrator requests `SERVER` with verified MFA and compliant device $\rightarrow$ **ALLOW**.
2. **SCENARIO-02: Unauthorized Lateral Movement** &mdash; Employee attempts lateral leap into `SERVER` enclave $\rightarrow$ **BLOCK (RBAC Gate)**.
3. **SCENARIO-03: Untrusted & Unhealthy Endpoint** &mdash; Manager requests `FINANCE` from compromised/jailbroken endpoint $\rightarrow$ **BLOCK**.
4. **SCENARIO-04: Anomalous Off-Hours Access** &mdash; Manager requests `HR` at 03:30 AM outside operating hours $\rightarrow$ **ADDITIONAL_VERIFICATION**.
5. **SCENARIO-05: High-Frequency Brute-Force Burst** &mdash; Automated tool making repeated rapid queries $\rightarrow$ **BLOCK (Behavioral Defense)**.
6. **SCENARIO-06: Blacklisted Threat Intel IP** &mdash; Request originating from a known Tor exit node or botnet C2 $\rightarrow$ **BLOCK (Threat Intel)**.
7. **SCENARIO-07: High-Sensitivity Asset Step-Up** &mdash; Manager requests financial treasury without prior MFA $\rightarrow$ **ADDITIONAL_VERIFICATION**.
8. **SCENARIO-08: Stale Identity / Session Hijacking** &mdash; Unverified/stale token indicative of cookie theft $\rightarrow$ **BLOCK**.
9. **SCENARIO-09: Rapid Sequence Hopping Anomaly** &mdash; Script scraping personnel directory $\rightarrow$ **BLOCK**.
10. **SCENARIO-10: Provisional Trust MFA Challenge** &mdash; Roaming domestic employee with score ~77.0 $\rightarrow$ **ADDITIONAL_VERIFICATION**.

---

## 5. Demonstration Accounts

The platform includes pre-seeded demonstration accounts with securely hashed passwords:

| Role | Username | Password | Permitted Resources |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `AdminPassword123!` | All resources (`HR`, `FINANCE`, `SERVER`, `EMPLOYEE_RECORDS`) |
| **Manager** | `manager` | `ManagerPassword123!` | `HR` (READ/WRITE), `FINANCE` (MFA Step-Up), `EMPLOYEE_RECORDS` (READ) |
| **Employee** | `employee` | `EmployeePassword123!` | `EMPLOYEE_RECORDS` (READ), `HR` (READ) |

*Step-2 Multi-Factor Authentication Demonstration OTP Code:* `739201`

---

## 6. Technology Stack

- **Backend:** Python 3.11+, Flask 3.1, Flask-SQLAlchemy 3.1, Werkzeug (PBKDF2-HMAC password hashing)
- **Database:** SQLite 3 (Persistent local storage at `instance/zero_trust.db`)
- **Frontend:** Semantic HTML5, Vanilla CSS3 (Custom design system with CSS custom properties), JavaScript ES6+
- **Visualizations:** Chart.js 4.4 (Timeline, Doughnut, Bar, Radar), SVG interactive network canvas & radial gauges
- **Testing:** pytest 9.1 with automated test suite covering authentication, RBAC, IACTE, decisions, and simulations

---

## 7. Windows PowerShell Installation & Launch Guide

Execute the following commands in **Windows PowerShell** inside the project root directory (`c:\Users\mercy\Downloads\ZERO-TRUST-NETWORK`):

### Step 1: Verify Python & Environment
```powershell
python --version
# Output should be Python 3.11.x or compatible
```

### Step 2: Create and Activate Virtual Environment (Optional / Recommended)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Local Environment
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```

### Step 5: Initialize SQLite Database & Schema
```powershell
python scripts/init_db.py
```

### Step 6: Seed Demonstration Accounts, Policies & Attack Scenarios
```powershell
python scripts/seed_demo_data.py
```

### Step 7: Run Automated Test Suite
```powershell
pytest -v
```
*(All 31 unit and integration tests will execute and pass).*

### Step 8: Start the Security Console Server
```powershell
python app.py
```

### Step 9: Open in Browser
Open your browser and navigate to:
```
http://127.0.0.1:5000
```
- Public Overview Portal: `http://127.0.0.1:5000/`
- Authentication Console: `http://127.0.0.1:5000/login`
- Security Command Center: `http://127.0.0.1:5000/dashboard`
- Access Request Simulator: `http://127.0.0.1:5000/simulator`
- Network Topology: `http://127.0.0.1:5000/network-map`
- Attack Simulation Lab: `http://127.0.0.1:5000/simulation-lab`

---

## 8. Automated Test Coverage Overview

The test suite in `tests/` executes 31 dedicated tests:

- **`test_authentication.py`** (6 tests): Valid login, password mismatch rejection, uniform error anti-enumeration, account lockout after 5 failures, session termination, route redirection.
- **`test_rbac.py`** (6 tests): Permitted access, employee server barrier, manager server barrier, read vs admin operation permissions, high trust score inability to bypass RBAC denial.
- **`test_iacte.py`** (6 tests): Sum of weights equals 1.00, maximum score 100.0, minimum score 0.0, exact factor contribution mathematics, clamping bounds, token normalizer.
- **`test_access_decisions.py`** (5 tests): Boundary edge cases (`59.99` Block, `60.00` Verify, `80.00` Verify, `80.01` Allow), step-up MFA challenge elevation to Allow.
- **`test_simulations.py`** (4 tests): Individual scenario execution, lateral movement block scenario, full 10-scenario suite execution with 100% pass rate, disposable run reset preserving audit trail.
- **`test_audit_logs.py`** (4 tests): Failed login event logging, non-admin 403 authorization lock on compliance logs, admin log access, CSV export streaming.

Run anytime with:
```powershell
pytest -v
```

---

## 9. Project Directory Structure

```
zero-trust-platform/
│
├── app.py                      # Flask application factory, security headers, context processor
├── config.py                   # Development, testing, and production configuration
├── requirements.txt            # Python dependencies
├── .env.example                # Sample environment configuration
├── .gitignore                  # Git ignore rules for virtualenvs, SQLite, caches
├── README.md                   # Complete architectural guide and setup instructions
│
├── models/                     # SQLAlchemy database models
│   ├── __init__.py             # DB instance and model exports
│   ├── role.py                 # Role model (Administrator, Manager, Employee)
│   ├── user.py                 # User model with password hashing & lockout
│   ├── resource.py             # Micro-segmented protected resources
│   ├── policy.py               # RBAC policies linking Roles, Resources, and Thresholds
│   ├── access_request.py       # Evaluated request records and outcomes
│   ├── trust_evaluation.py     # Detailed 7-factor numerical breakdowns
│   ├── simulation.py           # Simulation scenarios and run records
│   ├── audit_log.py            # Immutable compliance audit log
│   └── security_alert.py       # Incident alerts and threat tracking
│
├── security/                   # Core Zero Trust security engines
│   ├── __init__.py             # Security exports
│   ├── authentication.py       # Credential verification, anti-CSRF, lockout defense
│   ├── rbac.py                 # Role-Based Access Control evaluator
│   ├── iacte.py                # Intelligent Adaptive Continuous Trust Engine (7 factors)
│   ├── policy_engine.py        # Resource-specific threshold & MFA evaluation
│   ├── decision_engine.py      # Unified 12-step Zero Trust pipeline
│   └── session_security.py     # Decorators: @login_required, @role_required, @csrf_protect
│
├── services/                   # Business logic and reporting
│   ├── __init__.py
│   ├── access_service.py       # Access requests and secondary MFA OTP challenges
│   ├── dashboard_service.py    # Database-backed metrics, timelines, factor radars
│   ├── simulation_service.py   # Single & suite attack simulation runner
│   └── report_service.py       # CSV compliance reporting
│
├── routes/                     # Modular Flask Blueprints
│   ├── __init__.py
│   ├── landing_routes.py       # Public portal (/)
│   ├── auth_routes.py          # Login, logout, session management
│   ├── dashboard_routes.py     # Command center and Chart.js feeds
│   ├── simulator_routes.py     # Interactive Access Request Simulator
│   ├── network_routes.py       # Topology and micro-segmentation API
│   ├── simulation_routes.py    # Attack & Threat Lab API
│   ├── user_routes.py          # User and identity management (Admin)
│   ├── resource_routes.py      # Enclave asset inventory
│   ├── policy_routes.py        # Policy engine matrix configuration
│   ├── audit_routes.py         # Compliance audit log viewer & CSV export
│   ├── analytics_routes.py     # Detailed statistical reports & export
│   └── settings_routes.py      # Threshold configuration and demo reset
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Master layout with responsive sidebar & topbar
│   ├── landing.html            # Public architectural homepage
│   ├── login.html              # Cyber-branded sign-in with quick-fill
│   ├── dashboard.html          # Admin security command center
│   ├── simulator.html          # Interactive trust simulator & SVG gauge
│   ├── network_map.html        # Interactive SVG topology packet simulator
│   ├── simulation_lab.html     # 10 attack vector simulation cards & suite runner
│   ├── users.html              # User management & password reset modal
│   ├── resources.html          # Protected enclave inventory
│   ├── policies.html           # Policy engine matrix configuration
│   ├── audit_logs.html         # Audit trail with search, filters, and CSV export
│   ├── analytics.html          # Statistical reports & incident log
│   ├── settings.html           # Threshold boundaries display & demo reset
│   └── errors/
│       ├── 403.html            # Forbidden access
│       ├── 404.html            # Not found
│       └── 500.html            # Internal server anomaly
│
├── static/
│   ├── css/
│   │   ├── design-system.css   # Color palette tokens, badges, buttons, cards
│   │   ├── main.css            # Sidebar layout, topbar, modals, toasts
│   │   ├── dashboard.css       # Metric cards & Chart.js layouts
│   │   ├── simulator.css       # Radial SVG gauge & factor sliders
│   │   ├── network-map.css     # SVG network canvas & flow pulse animations
│   │   ├── simulation-lab.css  # Scenario card deck & suite banner
│   │   └── responsive.css      # Mobile drawer & accessibility queries
│   └── js/
│       ├── main.js             # Theme toggle, mobile drawer, toasts
│       ├── dashboard.js        # Chart.js initialization & live feed refresh
│       ├── simulator.js        # Gauge animation, factor sliders, MFA challenge
│       ├── network-map.js      # Packet transmission animation & lateral block
│       └── simulation-lab.js   # Scenario single & suite execution runners
│
├── scripts/
│   ├── init_db.py              # Database schema initialization
│   └── seed_demo_data.py       # Seeds roles, users, resources, policies, scenarios
│
├── tests/                      # Automated Pytest suite (31 tests)
│   ├── conftest.py             # Test app & authenticated client fixtures
│   ├── test_authentication.py  # Login, lockout, logout tests
│   ├── test_rbac.py            # RBAC enforcement & priority tests
│   ├── test_iacte.py           # Mathematical formula & contribution tests
│   ├── test_access_decisions.py# Threshold boundary edge cases (59.99, 60.00, etc.)
│   ├── test_simulations.py     # Attack suite execution tests
│   └── test_audit_logs.py      # Event logging & compliance export tests
│
└── instance/
    └── zero_trust.db           # Persistent SQLite database store
```

---

## 10. Educational & Academic Research Disclaimer

This project is an educational and engineering simulation developed for academic demonstration and research into Zero Trust network principles. All threat indicators, IP reputations, and network topologies are simulated in a controlled local environment and do not interact with live external infrastructure or real-world enterprise assets.
