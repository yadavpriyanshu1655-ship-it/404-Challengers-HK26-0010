# CyberShield AI — Intelligent Cyber Threat Detection

[![Team](https://img.shields.io/badge/Team-404%20Challengers-blue.svg)](https://github.com/yadavpriyanshu1655-ship-it/404-Challengers-HK26-0010)
[![Challenge](https://img.shields.io/badge/Official%20Challenge-ABCS--01-red.svg)](#official-problem-abcs-01)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.14-green.svg)](#technology-stack)
[![Frontend](https://img.shields.io/badge/Frontend-React%20%7C%20Vite%20%7C%20Tailwind-cyan.svg)](#technology-stack)
[![Testing](https://img.shields.io/badge/Tests-Pytest%20Passing-brightgreen.svg)](#running-tests)

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

## System Architecture & Detection Strategy

```
                              ┌────────────────────────┐
                              │  Security Log Stream   │
                              │  (CSV Batch / Webhook) │
                              └───────────┬────────────┘
                                          │
                     ┌────────────────────┴───────────────────┐
                     ▼                                        ▼
         ┌───────────────────────┐                ┌───────────────────────┐
         │ Layer 1: Rule Engine  │                │ Layer 2: Anomaly ML   │
         │ Deterministic Rules   │                │ IsolationForest       │
         └───────────┬───────────┘                └───────────┬───────────┘
                     │                                        │
                     └────────────────────┬───────────────────┘
                                          ▼
                             ┌─────────────────────────┐
                             │ Layer 3: Classifier AI  │
                             │ Supervised Threat Model │
                             └────────────┬────────────┘
                                          ▼
                             ┌─────────────────────────┐
                             │ Layer 4: Risk Assessor  │
                             │ Multi-Factor 0-100 Score│
                             └────────────┬────────────┘
                                          ▼
                             ┌─────────────────────────┐
                             │ Real-Time Alert Engine  │
                             │ WebSocket Stream + DB   │
                             └────────────┬────────────┘
                                          ▼
                             ┌─────────────────────────┐
                             │ React + Tailwind SOC    │
                             │ Live Visual Dashboard   │
                             └─────────────────────────┘
```

- **Layer 1 (Deterministic Fast Path):** Identifies obvious high-rate signatures within rolling 10-minute windows (e.g., $\ge 5$ failed authentications, password spraying across multiple targets).
- **Layer 2 (Unsupervised Anomaly Model):** Uses an `IsolationForest` to discover statistical and temporal outliers that deviate from baseline behavior.
- **Layer 3 (Supervised Threat Model):** Classifies complex attack vectors with probability distributions and feature importance scores.
- **Layer 4 (Calibrated Risk Engine):** Computes an explainable 0–100 composite score factoring base severity, anomaly depth, asset sensitivity, and attack rate.

---

## Project Structure

```
CyberShield/
├── .gitignore                    # Exclusions for environments, bytecode, logs, builds
├── README.md                     # Comprehensive project documentation
├── PHASE_STATUS.md               # Implementation phases and milestone status
├── backend/
│   ├── main.py                   # FastAPI application entrypoint
│   ├── requirements.txt          # Backend dependencies
│   ├── sample_logs.csv           # Baseline synthetic security telemetry
│   ├── data/                     # Ingestion datasets and training data
│   │   ├── .gitkeep
│   │   └── sample_logs.csv
│   ├── models/                   # Entity schemas and ML model artifacts
│   │   └── __init__.py
│   └── tests/                    # Pytest test suite
│       ├── __init__.py
│       └── test_mvp.py
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
- [ ] **Phase 02:** Backend modularization, enhanced SQLite schema, Scikit-learn anomaly/classifier models, and Pytest coverage.
- [ ] **Phase 03:** React + Vite + Tailwind CSS SOC dashboard with real-time WebSocket alert streaming and incident triage drawer.
- [ ] **Phase 04:** End-to-end synthetic attack scenarios, performance benchmarks, and hackathon demonstration readiness.

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
# Run test suite with Pytest
pytest backend/tests

# Alternatively run with Python's built-in unittest runner
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
