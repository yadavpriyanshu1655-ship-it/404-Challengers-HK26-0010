# CyberShield AI — Intelligent Cyber Threat Detection

[![Team](https://img.shields.io/badge/Team-404%20Challengers-blue.svg)](https://github.com/yadavpriyanshu1655-ship-it/404-Challengers-HK26-0010)
[![Challenge](https://img.shields.io/badge/Official%20Challenge-ABCS--01-red.svg)](#official-problem-abcs-01)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.14-green.svg)](#technology-stack)
[![Frontend](https://img.shields.io/badge/Frontend-React%20%7C%20Vite%20%7C%20Tailwind-cyan.svg)](#technology-stack)
[![Tests](https://img.shields.io/badge/Tests-48%2F48%20Passing-brightgreen.svg)](#running-tests)

Developed by hackathon team **404 Challengers** (`HK26-0010`), **CyberShield AI** is an intelligent, explainable security operations and threat detection platform. It ingests enterprise security telemetry, isolates behavioural anomalies, classifies sophisticated cyber attacks, calculates multi-factor risk scores, and dispatches real-time security alerts to an interactive SOC analyst dashboard.

---

## Official Problem: ABCS-01

**ABCS-01 — Intelligent Cyber Threat Detection** requires building an end-to-end security telemetry intelligence system capable of detecting, analyzing, and mitigating modern cyber threats in real time.

### Core Objectives & The 5 Official Requirements

1. **AI-Based Threat Detection:** Supervised machine learning algorithms trained to detect and classify multi-stage attack patterns (e.g., brute force, credential stuffing, privilege escalation, data exfiltration, distributed reconnaissance).
2. **Anomaly Detection:** Unsupervised outlier detection (`IsolationForest`) identifying zero-day threats, unusual volume spikes, non-standard operating hours, and atypical entity behaviour without predefined signatures.
3. **Threat Risk Assessment:** Multi-factor risk calculation engine mapping incidents to a normalized 0–100 risk score, incorporating asset criticality, attack velocity, anomaly deviation, and MITRE ATT&CK taxonomy.
4. **Real-Time Security Alerts:** Instant push notification mechanism (WebSockets) providing live alert feeds, deduplication, alert aggregation, and analyst triage lifecycle management (`Open` $\rightarrow$ `In Progress` $\rightarrow$ `Resolved`).
5. **Security Dashboard:** High-density, responsive SOC console (React + Vite + Tailwind CSS) featuring telemetry metrics, severity distributions, temporal attack trends, and interactive alert inspection drawers.

---

## Technology Stack

| Domain | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend Framework** | React (Vite) | High-performance component architecture for SOC interface |
| **Styling & UI** | Tailwind CSS + Lucide Icons | Responsive dark-mode SOC console design system |
| **Visualizations** | Recharts / Native SVG | Real-time incident velocity and severity distribution charts |
| **Backend Framework** | Python + FastAPI + Uvicorn | High-concurrency async REST API and WebSocket broadcast hub |
| **Data Processing** | Pandas + NumPy | Rolling-window aggregation, telemetry normalization, feature extraction |
| **Machine Learning** | Scikit-learn | `IsolationForest` (unsupervised anomaly) and `RandomForest` (classification) |
| **Persistence** | SQLite (WAL Mode) | Lightweight, ACID-compliant relational storage with indexed tables |
| **Testing & Quality** | Pytest + HTTPX TestClient | Comprehensive unit, integration, and security simulation testing |

---

## Rule-Based Threat Detection Engine

CyberShield AI provides a configurable, explainable detection engine (`backend/detection.py`) operating directly on normalized security events.

### Core Detection Rules

| Rule Name | Severity | Default Threshold | Description | MITRE Technique |
| :--- | :---: | :--- | :--- | :--- |
| **Repeated Failed Logins** | **High** | $\ge 5$ failures in $\le 10$ mins | Flags sustained authentication failures from the same source IP / user, preventing alert fatigue by ignoring isolated single failures. | `T1110.001` (Password Guessing) |
| **Success Following Repeated Failures** | **Critical** | $\ge 3$ failures followed by success in $\le 10$ mins | Identifies successful authentications immediately preceded by repeated failed attempts, indicating potential credential cracking or account compromise. | `T1110.001` (Password Guessing) |
| **Unusually High Login Frequency** | **High** | $\ge 10$ attempts in $\le 2$ mins | Flags volumetric burst velocities exceeding human capabilities, identifying automated credential stuffing or spray attacks. | `T1110.003` (Password Spraying) |
| **Unusual Login Hours** | **Medium / High** | $> 2$h outside baseline hours | Evaluates user logins against an established behavioral baseline ($\ge 5$ prior logins). **Strictly requires baseline evidence before alerting.** | `T1078` (Valid Accounts) |
| **Suspicious Login Behavioral Shift** | **High** | Unprecedented network subnet | Identifies authentications from unfamiliar subnets for users with established historical baselines ($\ge 8$ logins). | `T1078.003` (Local Accounts) |

### Explainable Finding Structure (`ThreatAlert`)
Every generated finding provides full evidentiary provenance:
- **`alert_id`**: Deterministic sequential identifier (`CS-ALERT-0001`).
- **`rule_name`**: Exact detection rule triggered.
- **`timestamp`**: ISO-8601 UTC trigger timestamp.
- **`entity_type` & `entity_value`**: Target subject (e.g., `source_ip: 203.0.113.100` or `username: admin`).
- **`severity`**: Contextual severity rating (`Critical`, `High`, `Medium`, `Low`).
- **`evidence_strength`**: Confidence level (`Strong`, `Moderate`, `Weak`).
- **`explanation`**: Plain-English rationale detailing what occurred.
- **`observed_value` & `threshold`**: Concrete metrics vs. configured bounds (e.g., `6 failed attempts in 4.5m` vs. `threshold: >= 5 in <= 10m`).
- **`recommended_investigation_step`**: Prescriptive SOC remediation playbook action.
- **`related_event_ids`**: SHA-256 fingerprints of contributing telemetry records.
- **`fingerprint`**: Deterministic cryptographic hash preventing duplicate alerts on repeated batch runs.

### End-to-End Ingestion & Detection Usage
```python
from backend.ingestion import SecurityLogIngestion
from backend.detection import ThreatDetectionEngine, DetectionConfig

# 1. Ingest raw telemetry
ingestion = SecurityLogIngestion()
result = ingestion.process_file("backend/data/synthetic_logs.csv")

# 2. Configure detection thresholds
config = DetectionConfig(
    failed_login_threshold=5,
    failed_login_window_minutes=10.0,
    preceding_failures_threshold=3,
    high_frequency_threshold=10,
)
engine = ThreatDetectionEngine(config=config)

# 3. Detect threats and inspect explainable findings
alerts = engine.detect(result)
for alert in alerts:
    print(f"[{alert.severity}] {alert.rule_name} on {alert.entity_value}: {alert.explanation}")
    print(f"Action: {alert.recommended_investigation_step}")
```

---

## Security Event Schema

| Field | Type | Required | Description | Supported Aliases |
| :--- | :--- | :---: | :--- | :--- |
| `timestamp` | `string` | **Yes** | Normalized ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) | `time`, `datetime`, `event_time`, `@timestamp`, `date`, `log_time` |
| `source_ip` | `string` | **Yes** | Validated source IPv4 or IPv6 address | `src_ip`, `ip`, `client_ip`, `ip_address`, `source_address`, `host_ip` |
| `destination_ip` | `string` | No | Target network address (defaults to `10.0.0.1`) | `dest_ip`, `dst_ip`, `server_ip`, `target_ip`, `target_address` |
| `username` | `string` | **Yes** | User, service account, or subject initiating the action | `user`, `account`, `user_name`, `user_id`, `login_id`, `actor` |
| `event_type` | `string` | **Yes** | Normalized lowercase event type (`login`, `file_access`, `sudo`) | `event`, `action`, `type`, `activity`, `event_name`, `method` |
| `status` | `string` | **Yes** | Normalized action outcome (`success`, `failed`, `denied`, `error`) | `result`, `outcome`, `action_result`, `state`, `disposition` |
| `resource` | `string` | No | URI, endpoint, or target system file (defaults to `/`) | `uri`, `url`, `endpoint`, `path`, `target`, `service` |
| `payload_size` | `integer` | No | Transferred payload bytes (defaults to `0`) | `bytes`, `size`, `bytes_sent`, `content_length`, `length` |
| `fingerprint` | `string` | Auto | Deterministic SHA-256 hash for deduplication | Generated automatically from canonical event values |

---

## Project Structure

```
CyberShield/
├── .gitignore                    # Exclusions for environments, bytecode, logs, builds
├── README.md                     # Comprehensive project documentation
├── PHASE_STATUS.md               # Implementation phases and milestone status
├── backend/
│   ├── detection.py              # Configurable rule-based threat detection engine
│   ├── ingestion.py              # Standalone Security Log Ingestion engine
│   ├── main.py                   # FastAPI application entrypoint
│   ├── requirements.txt          # Backend dependencies
│   ├── sample_logs.csv           # Baseline synthetic security telemetry
│   ├── data/                     # Ingestion datasets and training data
│   │   ├── .gitkeep
│   │   ├── sample_logs.csv
│   │   └── synthetic_logs.csv    # Labeled synthetic security telemetry dataset
│   ├── models/                   # Entity schemas and ML model artifacts
│   │   ├── __init__.py
│   │   ├── alert.py              # ThreatAlert model
│   │   └── event.py              # SecurityEvent, IngestionResult & RejectedRow models
│   └── tests/                    # Pytest test suite
│       ├── __init__.py
│       ├── test_detection.py     # 23 tests: rules, boundaries, baselines, deduplication
│       ├── test_ingestion.py     # 20 tests: ingestion, schemas, validation, pandas
│       └── test_mvp.py           # 5 tests: MVP regression tests
└── frontend/                     # React + Vite + Tailwind dashboard
    ├── index.html
    └── assets/
        ├── app.js
        └── styles.css
```

---

## Planned Features Roadmap

- [x] **Phase 00:** Architecture proposal, environment baseline inspection, and dependency mapping.
- [x] **Phase 01:** Foundation establishment, approved directory structure, Git configuration, and documentation.
- [x] **Phase 02:** Standalone Security Log Ingestion module, event schema specification, synthetic telemetry, and Pytest validation.
- [x] **Phase 03:** Explainable rule-based threat detection engine, configurable thresholds, behavioral baseline profiles, and 48 passing tests.
- [ ] **Phase 04:** Unsupervised anomaly detection (`IsolationForest`) and multi-factor risk scoring engine.
- [ ] **Phase 05:** React + Vite + Tailwind CSS SOC dashboard with real-time WebSocket alert streaming and incident triage drawer.
- [ ] **Phase 06:** End-to-end synthetic attack scenarios, performance benchmarks, and hackathon demonstration readiness.

---

## Development Commands

### Prerequisites
- Python $\ge$ 3.10 (Tested on Python 3.14)
- Node.js $\ge$ 18.0 (Tested on Node.js v24.21.0, npm 12.0.2)

### 1. Backend Setup & Execution
```bash
# Optional: Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Start the FastAPI development server
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
The backend API and interactive documentation will be available at:
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

### 2. Running Tests
```bash
# Run full test suite with Pytest
pytest backend/tests

# Run specifically the detection test suite
pytest backend/tests/test_detection.py -v

# Run specifically the log ingestion test suite
pytest backend/tests/test_ingestion.py -v

# Run legacy unittest regression suite
python3 -m unittest backend/tests/test_mvp.py
```

### 3. Frontend Development
```bash
# Navigate to frontend directory
cd frontend

# Install frontend dependencies
npm install

# Start Vite development server
npm run dev
```

---

## Team & Contribution

- **Team:** 404 Challengers (`HK26-0010`)
- **Hackathon:** All-India Cybersecurity Hackathon 2026
- **Lead Contact:** `yadavpriyanshu1655@gmail.com`
