# CyberShield AI — Project Implementation Status

**Project:** CyberShield AI  
**Team:** 404 Challengers (`HK26-0010`)  
**Challenge:** ABCS-01 — Intelligent Cyber Threat Detection  
**Repository:** `https://github.com/yadavpriyanshu1655-ship-it/404-Challengers-HK26-0010.git`  
**Current Phase:** Phase 05 Completed — Threat Risk Assessment & Incident Correlation Delivered  

---

## Phase Execution Matrix

| Phase | Phase Name | Status | Description |
| :---: | :--- | :---: | :--- |
| **00** | Architecture Proposal & Environment Baseline | **DONE** | Workspace inspection, Git tracking analysis, runtime verification, and 5-requirement architecture blueprint. |
| **01** | Foundation & Project Structure Establishment | **DONE** | Project structure scaffolding (`backend/data`, `backend/models`, `backend/tests`, `frontend`), `.gitignore` refinement, comprehensive documentation (`README.md`, `PHASE_STATUS.md`), and test validation. |
| **02** | Security Log Ingestion Module | **DONE** | Reusable, standalone Python ingestion module (`backend/ingestion.py`), canonical `SecurityEvent` schema, synthetic benchmark dataset (`synthetic_logs.csv`), timestamp normalization, duplicate detection, resilient rejection, and 25 passing Pytest tests. |
| **03** | Rule-Based Threat Detection Engine | **DONE** | Configurable, explainable threat detection engine (`backend/detection.py`), `ThreatAlert` model (`alert.py`), 5 core detection rules, behavioral baseline profiles, alert deduplication, and 48 passing Pytest tests. |
| **04** | ML Anomaly Detection Pipeline | **DONE** | Reproducible Scikit-learn `IsolationForest` pipeline (`backend/ml/anomaly.py`), `SecurityFeatureExtractor` (`features.py`), safe joblib model persistence, zero data leakage, held-out evaluation report, non-malicious disclaimers, and 60 passing Pytest tests. |
| **05** | Threat Risk Assessment & Incident Correlation | **DONE** | 4-Tier severity model (Low, Medium, High, Critical), independent score dimensions, transparent additive risk calculation, evidence-based temporal clustering, strict non-confirmation of anomaly-only findings, and 70 passing Pytest tests. |
| **06** | Real-Time Security Alerts & Telemetry API | **PENDING APPROVAL** | FastAPI WebSocket streaming hub (`/ws/alerts`), live event broadcasting, incident triage lifecycle endpoints, and deduplicated notification dispatch. |
| **07** | React + Vite + Tailwind CSS SOC Dashboard | **PLANNED** | Production SOC dashboard with dark-mode theme, live WebSocket push alerts, incident triage drawer, telemetry analytics, and interactive CSV/streaming ingestion station. |

---

## Phase 05 Milestone Deliverables

- [x] **4-Tier Severity Model (`backend/risk_assessment.py`):**
  - Calibrated numerical bands: Low ($0-39$), Medium ($40-64$), High ($65-84$), and Critical ($85-100$).
  - Strictly distinguishes operational priority and response SLAs.
- [x] **Separation of Analytical Dimensions (`backend/models/risk.py`):**
  - `severity`: Recommended operational impact tier (`Critical`, `High`, `Medium`, `Low`).
  - `confidence`: Evidentiary certainty ($0.0 \dots 1.0$) and categorical rating (`High`, `Medium`, `Low`).
  - `anomaly_score`: Statistical ML deviation ($0.0 \dots 1.0$) reported independently without polluting severity.
  - `composite_risk_score`: Calibrated priority score ($0 \dots 100$).
- [x] **Transparent Additive Risk Factor Model:**
  - Itemized `RiskFactor` breakdown recording rule baseline points ($+20$ to $+80$), ML anomaly points ($+5$ to $+15$), privileged target bonus ($+10$), external ingress bonus ($+5$), multi-rule synergy ($+10$), and velocity burst ($+5$).
  - Detailed narrative explanations synthesized for every assessed incident.
- [x] **Evidence-Based Temporal Clustering:**
  - Groups telemetry strictly by entity (`username` or `source_ip`) within a configurable sliding window ($\le 15.0$ minutes).
  - Unrelated entities or temporally distant events remain independent.
- [x] **Strict Non-Confirmation Constraint:**
  - Incidents derived solely from ML anomaly findings are marked `is_confirmed = False`, `confirmation_status = "Unconfirmed Anomaly"`, with confidence capped at $\le 0.45$ ("Low").
  - An incident is never confirmed as an attack without corroborating rule or signature evidence.
- [x] **Prescriptive Safe Defensive Recommendations:**
  - Actionable, non-destructive SOC guidance (out-of-band identity verification, active session termination, credential reset, edge rate-limiting).
- [x] **Full Pytest Suite (`backend/tests/test_risk_assessment.py`):**
  - 10 new dedicated test cases covering severity boundaries, dimension separation, transparent combination, related vs. unrelated correlation, deduplication, prioritization, non-confirmation, and missing context.
  - **Full Test Suite Results:** **70 passed in 2.81s** across all test suites (100% pass rate).

---

## Next Steps (Phase 06 Gate)
- Awaiting user approval to proceed to **Phase 06: Real-Time Security Alerts & Telemetry API**.
