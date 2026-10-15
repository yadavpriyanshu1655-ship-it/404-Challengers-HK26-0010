# CyberShield AI — Intelligent Cyber Threat Detection

[![Team](https://img.shields.io/badge/Team-404%20Challengers-blue.svg)](https://github.com/yadavpriyanshu1655-ship-it/404-Challengers-HK26-0010)
[![Challenge](https://img.shields.io/badge/Official%20Challenge-ABCS--01-red.svg)](#official-problem-abcs-01)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.14-green.svg)](#technology-stack)
[![Frontend](https://img.shields.io/badge/Frontend-React%20%7C%20Vite%20%7C%20Tailwind-cyan.svg)](#technology-stack)
[![Tests](https://img.shields.io/badge/Tests-60%2F60%20Passing-brightgreen.svg)](#running-tests)

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
| **Machine Learning** | Scikit-learn (Isolation Forest) | Reproducible unsupervised outlier discovery & categorical preprocessing |
| **Persistence** | SQLite (WAL Mode) & Joblib | Lightweight relational storage & serialized ML artifact persistence |
| **Testing & Quality** | Pytest + HTTPX TestClient | Comprehensive unit, integration, and security simulation testing |

---

## Machine-Learning Anomaly Detection (`IsolationForest`)

CyberShield AI provides a reproducible, unsupervised anomaly detection pipeline (`backend/ml/anomaly.py`) powered by **Scikit-learn's Isolation Forest**.

### Pipeline Architecture & Leakage Prevention
```
                              ┌────────────────────────┐
                              │ Training Telemetry     │
                              │ (Synthetic Baseline)   │
                              └───────────┬────────────┘
                                          │
                                          ▼
                              ┌────────────────────────┐
                              │ ColumnTransformer      │
                              │ fit_transform(X_train) │
                              └───────────┬────────────┘
                                          │
                                          ▼
                              ┌────────────────────────┐
                              │ IsolationForest.fit()  │
                              │ (Unsupervised Trees)   │
                              └───────────┬────────────┘
                                          │
                         ┌────────────────┴────────────────┐
                         ▼                                 ▼
             ┌───────────────────────┐         ┌───────────────────────┐
             │ Model Persistence     │         │ Held-Out Inference    │
             │ joblib.dump(artifact) │         │ transform() -> score()│
             └───────────────────────┘         └───────────────────────┘
```
- **Zero Data Leakage:** Preprocessing scalers (`StandardScaler`) and encoders (`OneHotEncoder`) are fit strictly on training telemetry (`fit()`), then applied without re-fitting to evaluation data (`transform()`).
- **Meaningful Extracted Features:**
  - Cyclical temporal coordinates: $\sin(2\pi \cdot \text{hour}/24)$, $\cos(2\pi \cdot \text{hour}/24)$.
  - Calendar indicators: `day_of_week`, `is_weekend`.
  - Log payload magnitude: $\log(1 + \text{payload\_size})$.
  - Contextual binary indicators: `is_failure`, `is_privileged_user`, `is_privileged_resource`, `is_external_ip`.
  - Categorical action type: `event_type` encoded with `handle_unknown='ignore'`.
- **Calibrated Scoring:** Raw decision function scores are converted into normalized probabilities in $[0.0, 1.0]$.
- **Separation of Concerns:** ML anomaly findings (`AnomalyFinding`) remain distinct from deterministic rule alerts (`ThreatAlert`).
- **Strict Non-Malicious Principle:** All anomaly outputs include an explicit disclaimer:  
  > *"Statistical anomaly indicator only; does not necessarily indicate malicious intent."*

### Held-Out Evaluation & Documented Limitations
Evaluation performed on held-out synthetic telemetry (`backend/data/held_out_telemetry.csv`):
- **Training Samples:** 40 baseline business events.
- **Held-Out Evaluation Samples:** 20 events (16 normal, 4 synthetic outliers).
- **Contamination Rate:** 0.10.
- **Detected Outliers:** 4 / 20 ($20.0\%$).
- **Mean Anomaly Score:** 0.448 across held-out distribution.
- **Documented Limitations:**
  1. *Unsupervised Nature:* Flags statistical deviations from the training distribution; benign anomalies (e.g., approved off-hours maintenance) may trigger elevated scores.
  2. *Contamination Sensitivity:* Model sensitivity depends on the `contamination` hyperparameter, requiring domain-specific calibration.
  3. *Synthetic Representation:* Initial baselines are trained on synthetic enterprise telemetry; production environments require real-world historical calibration.

### ML Pipeline Usage Example
```python
from backend.ingestion import SecurityLogIngestion
from backend.ml import AnomalyDetectionPipeline

# 1. Ingest baseline training telemetry
ingestion = SecurityLogIngestion()
train_events = ingestion.process_file("backend/data/training_telemetry.csv").events
test_events = ingestion.process_file("backend/data/held_out_telemetry.csv").events

# 2. Fit pipeline (leakage-free)
pipeline = AnomalyDetectionPipeline(n_estimators=100, contamination=0.1, random_state=42)
pipeline.fit(train_events)

# 3. Score held-out telemetry & persist
findings = pipeline.score(test_events)
pipeline.save("backend/models/anomaly_model.joblib")

for finding in findings:
    if finding.is_anomaly:
        print(f"[{finding.finding_id}] Anomaly on {finding.entity} (Score: {finding.anomaly_score}): {finding.contributing_factors}")
```

---

## Rule-Based Threat Detection Engine

Operates in parallel with ML models to catch known deterministic attack signatures:

| Rule Name | Severity | Default Threshold | Description | MITRE Technique |
| :--- | :---: | :--- | :--- | :--- |
| **Repeated Failed Logins** | **High** | $\ge 5$ failures in $\le 10$ mins | Flags sustained brute-force authentications from the same source IP / user. | `T1110.001` (Password Guessing) |
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
│   ├── main.py                   # FastAPI application entrypoint
│   ├── requirements.txt          # Backend dependencies
│   ├── sample_logs.csv           # Baseline synthetic security telemetry
│   ├── data/                     # Ingestion datasets and training data
│   │   ├── .gitkeep
│   │   ├── sample_logs.csv
│   │   ├── synthetic_logs.csv    # Labeled synthetic security telemetry dataset
│   │   ├── training_telemetry.csv# Baseline normal telemetry for ML training
│   │   └── held_out_telemetry.csv# Held-out evaluation telemetry
│   ├── ml/                       # Machine Learning subsystem
│   │   ├── __init__.py
│   │   ├── anomaly.py            # Isolation Forest anomaly detection pipeline
│   │   └── features.py           # Feature extraction & ColumnTransformer preprocessing
│   ├── models/                   # Entity schemas and ML model artifacts
│   │   ├── __init__.py
│   │   ├── alert.py              # ThreatAlert model
│   │   ├── anomaly.py            # AnomalyFinding & ModelEvaluationReport models
│   │   └── event.py              # SecurityEvent, IngestionResult & RejectedRow models
│   └── tests/                    # Pytest test suite (60 passing tests)
│       ├── __init__.py
│       ├── test_anomaly.py       # 12 tests: ML pipeline, leakage, persistence, reproducibility
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
- [x] **Phase 04:** Unsupervised machine-learning anomaly detection (`IsolationForest`), feature extraction, safe model persistence, and 60 passing tests.
- [ ] **Phase 05:** Composite multi-factor threat risk assessment engine (0-100 scale) and real-time alert correlation.
- [ ] **Phase 06:** React + Vite + Tailwind CSS SOC dashboard with real-time WebSocket alert streaming and incident triage drawer.

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
# Run full test suite across all 60 tests
pytest backend/tests

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
