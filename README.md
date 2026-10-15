# CyberShield AI — Intelligent Cyber Threat Detection

[![Team](https://img.shields.io/badge/Team-404%20Challengers-blue.svg)](https://github.com/yadavpriyanshu1655-ship-it/404-Challengers-HK26-0010)
[![Challenge](https://img.shields.io/badge/Official%20Challenge-ABCS--01-red.svg)](#official-problem-abcs-01)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.14-green.svg)](#technology-stack)
[![Frontend](https://img.shields.io/badge/Frontend-React%20%7C%20Vite%20%7C%20Tailwind-cyan.svg)](#technology-stack)
[![Tests](https://img.shields.io/badge/Tests-88%2F88%20Passing-brightgreen.svg)](#running-tests)

Developed by hackathon team **404 Challengers** (`HK26-0010`), **CyberShield AI** is an intelligent, explainable security operations and threat detection platform. It ingests enterprise security telemetry, isolates behavioural anomalies, classifies sophisticated cyber attacks, calculates multi-factor risk scores, and dispatches real-time security alerts to an interactive SOC analyst dashboard.

---

## Official Problem: ABCS-01

**ABCS-01 — Intelligent Cyber Threat Detection** requires building an end-to-end security telemetry intelligence system capable of detecting, analyzing, and mitigating modern cyber threats in real time.

### Core Objectives & The 5 Official Requirements

1. **AI-Based Threat Detection:** Supervised machine learning algorithms trained to detect and classify multi-stage attack patterns (e.g., brute force, credential stuffing, privilege escalation, data exfiltration, distributed reconnaissance).
2. **Anomaly Detection:** Unsupervised outlier detection (`IsolationForest`) identifying zero-day threats, unusual volume spikes, non-standard operating hours, and atypical entity behaviour without predefined signatures.
3. **Threat Risk Assessment:** Multi-factor risk calculation engine mapping incidents to a normalized 0–100 risk score, incorporating asset criticality, attack velocity, anomaly deviation, and MITRE ATT&CK taxonomy.
4. **Real-Time Security Alerts:** Instant push notification mechanism providing live alert feeds, deduplication, alert aggregation, and analyst triage lifecycle management (`Open` $\rightarrow$ `Investigating` $\rightarrow$ `Resolved` $\rightarrow$ `Dismissed`).
5. **Security Dashboard:** High-density, responsive SOC console (React + Vite + Tailwind CSS) featuring telemetry metrics, severity distributions, temporal attack trends, and interactive alert inspection drawers.

---

## Technology Stack

| Domain | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend Framework** | React (Vite) | High-performance component architecture for SOC interface |
| **Styling & UI** | Tailwind CSS + Lucide Icons | Responsive dark-mode SOC console design system |
| **Visualizations** | Recharts / Native SVG | Real-time incident velocity and severity distribution charts |
| **Backend Framework** | Python + FastAPI + Uvicorn | High-concurrency async REST API and detection pipeline |
| **API Contracts** | Pydantic v2 | Strict request/response validation and interactive OpenAPI docs |
| **Data Processing** | Pandas + NumPy | Rolling-window aggregation, telemetry normalization, feature extraction |
| **Machine Learning** | Scikit-learn (Isolation Forest) | Reproducible unsupervised outlier discovery & categorical preprocessing |
| **Risk & Correlation** | Python Risk Engine | Transparent multi-factor risk scoring (0-100) & incident correlation |
| **Persistence** | SQLite (WAL Mode) & Joblib | Lightweight relational storage & serialized ML artifact persistence |
| **Testing & Quality** | Pytest + Starlette TestClient | Comprehensive unit, integration, API contract, and security testing |

---

## REST API Documentation & Endpoints

CyberShield AI provides a full-featured REST API conforming to OpenAPI specifications. When the server is running, interactive documentation is accessible at `http://127.0.0.1:8000/docs` (Swagger UI) and `http://127.0.0.1:8000/redoc` (ReDoc).

| HTTP Method | Endpoint | Description | Request / Query Parameters | Response Schema |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Health check & system diagnostics | None | `HealthResponse` |
| `POST` | `/api/logs/upload` | Ingest security telemetry CSV file | `file: UploadFile` (Multipart, $\le 10$ MB) | `UploadLogsResponse` |
| `POST` | `/api/detection/run` | Trigger on-demand detection over persisted events | None | `DetectionRunResponse` |
| `GET` | `/api/events` | List paginated security events with filters | `limit`, `offset`, `username`, `source_ip`, `event_type`, `status`, `search` | `EventListResponse` |
| `GET` | `/api/events/{id}` | Retrieve specific security event details | `id: int` (Path parameter) | `SecurityEventSchema` |
| `GET` | `/api/alerts` | List paginated alerts & correlated incidents | `limit`, `offset`, `severity`, `status`, `entity`, `search` | `AlertListResponse` |
| `GET` | `/api/alerts/{id}` | Retrieve granular incident details & evidence | `id: int` (Path parameter) | `AlertResponse` |
| `PATCH` | `/api/alerts/{id}` | Update alert triage state | `payload: {"status": "Resolved"}` | `{"updated": true, "id": ..., "status": ...}` |
| `GET` | `/api/dashboard/stats` | Executive summary metrics & time trends | None | `DashboardStatsResponse` |
| `POST` | `/api/demo/sample` | Load demo telemetry and run pipeline | None | `{"message": ..., "valid_rows": ..., ...}` |
| `POST` | `/api/demo/reset` | Clear events, alerts, and anomalies | None | `{"reset": true, "message": ...}` |

---

## Threat Risk Assessment & Incident Correlation

CyberShield AI features a transparent, multi-factor risk engine (`backend/risk_assessment.py`) that correlates rule-based detections, ML anomalies, and contextual telemetry into unified, prioritized `CorrelatedIncident` entities.

### 4-Tier Severity Model

| Severity Tier | Composite Risk Score Band | Description | Typical Response SLA |
| :--- | :---: | :--- | :---: |
| **Critical** | **85 – 100** | High-confidence multi-stage attack or confirmed credential compromise (e.g., successful login following repeated brute-force failures targeting administrative accounts). | **Immediate (< 15 min)** |
| **High** | **65 – 84** | Serious attack activity (e.g., active brute-forcing, volumetric spray bursts, unprecedented external subnet shifts). | **< 1 hour** |
| **Medium** | **40 – 64** | Noticeable deviations from baseline behavior (e.g., unusual login hours, uncorroborated statistical anomalies). | **< 4 hours** |
| **Low** | **0 – 39** | Informational policy findings or minor single-point anomalies with low confidence. | **Next business day** |

### Transparent Additive Risk Factor Model
Every incident calculates a deterministic score in $[0, 100]$ using documented component adjustments:
- **Rule Evidence Baseline:** Critical rule $= +80$, High rule $= +65$, Medium rule $= +40$, Low rule $= +20$.
- **ML Anomaly Contribution:** $+5$ to $+15$ depending on Isolation Forest peak anomaly score.
- **Privileged Identity Target:** $+10$ when targeting accounts like `root`, `admin`, or sensitive system services.
- **External Network Ingress:** $+5$ when origin IP is from outside internal RFC 1918 private subnets.
- **Multi-Rule Synergy:** $+10$ when multiple distinct attack tactics match the same entity.
- **Velocity Burst:** $+5$ when $\ge 5$ correlated events occur within the correlation window.

### Key Governance Guarantees
1. **Strict Separation of Dimensions:** `severity` (impact tier), `confidence` ($0.0 \dots 1.0$), `anomaly_score` ($0.0 \dots 1.0$), and `composite_risk_score` ($0 \dots 100$) are calculated and reported independently.
2. **Evidence-Based Correlation:** Only groups events that share a common entity (`username` or `source_ip`) within a configurable sliding window ($\le 15.0$ minutes). **Unrelated entities and distant timestamps are never co-mingled.**
3. **Non-Confirmation Constraint:** **An incident is NEVER marked confirmed based solely on an anomaly score.** Anomaly-only clusters remain `is_confirmed = False`, `confirmation_status = "Unconfirmed Anomaly"`, with confidence capped at $\le 0.45$.
4. **Safe Defensive Recommendations:** All findings provide prescriptive, non-destructive SOC guidance (e.g., out-of-band verification, session token revocation, temporary ingress rate-limiting).

---

## Machine-Learning Anomaly Detection (`IsolationForest`)

- **Leakage-Free Preprocessing:** `ColumnTransformer` with `StandardScaler` and `OneHotEncoder` fit exclusively on training data.
- **Features Extracted:** Cyclical hour coordinates ($\sin, \cos$), log payload magnitude, day-of-week, privileged identity flags, external IP indicators, and categorical action types.
- **Model Persistence:** Safe serialization and deserialization using `joblib`.
- **Disclaimer:** All findings include: *"Statistical anomaly indicator only; does not necessarily indicate malicious intent."*

---

## Rule-Based Threat Detection Engine

| Rule Name | Severity | Default Threshold | Description | MITRE Technique |
| :--- | :---: | :--- | :--- | :--- |
| **Repeated Failed Logins** | **High** | $\ge 5$ failures in $\le 10$ mins | Flags sustained brute-force authentications. | `T1110.001` (Password Guessing) |
| **Success Following Repeated Failures** | **Critical** | $\ge 3$ failures followed by success in $\le 10$ mins | Identifies successful logins immediately preceded by repeated failures (account compromise). | `T1110.001` (Password Guessing) |
| **Unusually High Login Frequency** | **High** | $\ge 10$ attempts in $\le 2$ mins | Flags volumetric bursts exceeding human interaction capability. | `T1110.003` (Password Spraying) |
| **Unusual Login Hours** | **Medium / High** | $> 2$h outside baseline hours | Evaluates user logins against an established behavioral baseline ($\ge 5$ prior logins). | `T1078` (Valid Accounts) |
| **Suspicious Login Behavioral Shift** | **High** | Unprecedented network subnet | Identifies authentications from unfamiliar subnets for users with baseline history ($\ge 8$ logins). | `T1078.003` (Local Accounts) |

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
│   ├── main.py                   # FastAPI REST application entrypoint
│   ├── requirements.txt          # Backend dependencies
│   ├── risk_assessment.py        # Threat risk assessment & incident correlation engine
│   ├── sample_logs.csv           # Baseline synthetic security telemetry
│   ├── data/                     # Ingestion datasets and training data
│   │   ├── .gitkeep
│   │   ├── sample_logs.csv
│   │   ├── synthetic_logs.csv    # Labeled synthetic security telemetry dataset
│   │   ├── training_telemetry.csv# Baseline normal telemetry for ML training
│   │   └── held_out_telemetry.csv# Held-out evaluation telemetry
│   ├── db/                       # Persistence subsystem
│   │   ├── __init__.py
│   │   └── database.py           # SQLite connection, WAL mode, migrations, queries
│   ├── ml/                       # Machine Learning subsystem
│   │   ├── __init__.py
│   │   ├── anomaly.py            # Isolation Forest anomaly detection pipeline
│   │   └── features.py           # Feature extraction & ColumnTransformer preprocessing
│   ├── models/                   # Entity schemas and ML model artifacts
│   │   ├── __init__.py
│   │   ├── alert.py              # ThreatAlert model
│   │   ├── anomaly.py            # AnomalyFinding & ModelEvaluationReport models
│   │   ├── event.py              # SecurityEvent, IngestionResult & RejectedRow models
│   │   ├── isolation_forest.joblib # Persisted trained Isolation Forest model
│   │   └── risk.py               # CorrelatedIncident, RiskFactor & RiskSeverity models
│   ├── schemas/                  # Pydantic v2 REST API schemas
│   │   ├── __init__.py
│   │   └── api.py                # Health, Event, Alert, Dashboard & Error schemas
│   └── tests/                    # Pytest test suite (88 passing tests)
│       ├── __init__.py
│       ├── test_anomaly.py       # 12 tests: ML pipeline, leakage, persistence, reproducibility
│       ├── test_api.py           # 18 tests: FastAPI REST endpoints, uploads, filters, CORS
│       ├── test_detection.py     # 23 tests: rules, boundaries, baselines, deduplication
│       ├── test_ingestion.py     # 20 tests: ingestion, schemas, validation, pandas
│       ├── test_mvp.py           # 5 tests: MVP regression tests
│       └── test_risk_assessment.py # 10 tests: risk scoring, severity bands, correlation
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
- [x] **Phase 04:** Unsupervised machine-learning anomaly detection (`IsolationForest`), feature extraction, safe model persistence, and 60 passing tests.
- [x] **Phase 05:** Composite multi-factor threat risk assessment engine (0-100 scale), severity classification, incident correlation, and 70 passing tests.
- [x] **Phase 06:** FastAPI REST backend, Pydantic schemas, SQLite persistence, filtered queries, CORS, and 88 passing tests.
- [ ] **Phase 07:** React + Vite + Tailwind CSS SOC dashboard with real-time threat feed and interactive telemetry charts.

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

### 2. Running Tests
```bash
# Run full test suite across all 88 tests
pytest backend/tests

# Run specifically the REST API tests
pytest backend/tests/test_api.py -v

# Run specifically the risk assessment & correlation tests
pytest backend/tests/test_risk_assessment.py -v

# Run specifically the ML anomaly detection tests
pytest backend/tests/test_anomaly.py -v

# Run specifically the rule-based detection tests
pytest backend/tests/test_detection.py -v

# Run specifically the log ingestion tests
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
