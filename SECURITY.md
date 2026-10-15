# CyberShield AI — Security Policy & Quality Assurance Audit

**Official Problem:** ABCS-01 — Intelligent Cyber Threat Detection  
**Team:** 404 Challengers (`HK26-0010`)  
**Assessment Date:** October 2026  
**Status:** Audited & Verified  

---

## 1. Security Architecture & Threat Model

CyberShield AI is an intelligent, explainable security telemetry analysis platform designed to process authentication and system audit logs, isolate anomalies, detect multi-stage attack patterns, and provide actionable SOC incident triage.

### Attack Surface Analysis & Defensive Controls

| Attack Vector | Potential Impact | Implemented Mitigations | Verification Status |
| :--- | :--- | :--- | :---: |
| **Malicious File Uploads** | Remote code execution, disk exhaustion, server crashes | • Strict `.csv` extension verification<br>• Enforced 10 MB payload ceiling (`MAX_UPLOAD_BYTES`)<br>• In-memory decoding with stream disposal (zero disk writes)<br>• Null-byte (`\x00`) binary rejection | **Verified** (`test_security_input_validation_boundary_limits`) |
| **SQL Injection (SQLi)** | Data exfiltration, unauthorized modification, authentication bypass | • 100% parameterized queries (`?` bindings) across all endpoints<br>• Zero f-string or string concatenation in SQL commands<br>• Strict Pydantic v2 schema type enforcement | **Verified** (`test_security_sql_injection_resilience`) |
| **Cross-Site Scripting (XSS)** | Analyst session hijack, dashboard defacement | • React automated JSX escaping<br>• Inert database text storage for user identities and resources<br>• Structured JSON API response contracts | **Verified** (`test_security_xss_in_telemetry_stored_safely`) |
| **Information Leakage** | Architecture reconnaissance, credential discovery | • Global unhandled exception handler masks raw tracebacks<br>• Internal file paths and module names redacted from 500 errors<br>• Standardized safe `ErrorDetail` error payloads | **Verified** (`test_security_unhandled_exception_masks_stack_traces`) |
| **Cross-Origin Access (CORS)** | Unauthorized cross-site API querying | • Strict origin restriction whitelist (`ALLOWED_ORIGINS`)<br>• Wildcard (`*`) origin rejected in production and API configurations | **Verified** (`test_security_cors_restrictions`) |
| **Denial of Service (DoS)** | Memory exhaustion, CPU starvation via heavy payloads | • Client-side and server-side request deduplication<br>• Query pagination bounds (`ge=1`, `le=500` / `le=1000`, `ge=0`)<br>• Chunked file streaming with immediate size gating | **Verified** (`test_security_pagination_constraints_enforced`) |
| **Automated Destructive Actions** | Accidental lockout of legitimate administrative users | • Prescriptive safe defensive recommendations only<br>• Out-of-band verification required before credential revocation<br>• Zero automated account deletion or destructive network drops | **Verified** (`test_qa_isolated_failed_logins_never_flagged_as_attack`) |

---

## 2. Model Governance & Explainability Boundaries

### Isolation Forest Anomaly Detection Policy
1. **Non-Confirmation Constraint:**
   - Statistical outliers discovered by the Scikit-learn `IsolationForest` pipeline are **never automatically marked as confirmed incidents**.
   - Anomaly-driven incidents are tagged as `is_confirmed = False`, confidence is bounded ($\le 0.40$), and risk score is capped below High severity ($< 55$).
2. **Explicit Non-Maliciousness Disclaimer:**
   - Every anomaly finding includes an immutable disclaimer:
     > *"Statistical anomaly indicator only; does not necessarily indicate malicious intent."*
3. **Zero Data Leakage:**
   - Preprocessing scalers and categorical encoders are strictly fit on the training corpus and never on evaluation or incoming live batches.

---

## 3. Operational Boundaries & Known Limitations

> [!IMPORTANT]
> CyberShield AI is a hackathon prototype engineered for the ABCS-01 challenge. It is not rated for unmonitored production defense without human-in-the-loop SOC oversight.

1. **Synthetic Telemetry Baseline:**
   - The behavioral baseline models and Isolation Forest pipeline were trained and evaluated on synthetic enterprise telemetry. Real-world enterprise production networks exhibit higher variance, background noise, and concept drift requiring periodic re-tuning.
2. **TLS Termination:**
   - In production environments, CyberShield AI must sit behind a reverse proxy (e.g. Nginx, Envoy, or Cloudflare) enforcing TLS 1.3, rate-limiting, and Web Application Firewall (WAF) filtering.
3. **Ingestion Throughput:**
   - In-memory CSV batch ingestion is optimized for telemetry batches up to 10 MB. For enterprise-scale streaming (hundreds of megabytes per second), an external ingestion broker (Kafka, AWS Kinesis, or Redis Streams) is recommended.
4. **Relational Storage:**
   - The current storage engine uses SQLite with WAL mode (`cybershield.db`). While performant for single-node deployments, horizontal clustering requires migrating to PostgreSQL with connection pooling.

---

## 4. Vulnerability Disclosure & Quality Assurance

To report security vulnerabilities or quality concerns:
- **Lead Maintainer:** Priyanshu Yadav (`yadavpriyanshu1655@gmail.com`)
- **Team:** 404 Challengers (`HK26-0010`)
- **Protocol:** Responsible disclosure via direct maintainer contact.
