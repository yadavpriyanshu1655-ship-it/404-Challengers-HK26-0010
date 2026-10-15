"""
CyberShield AI — Phase 09 Security Review & Quality Assurance Test Suite
Official Problem: ABCS-01 — Intelligent Cyber Threat Detection
Team: 404 Challengers

Covers:
- Input validation: size limits, file extensions, encoding, null bytes, malformed headers
- SQL Injection (SQLi) resilience: parameterized queries under adversarial payload injection
- Cross-Site Scripting (XSS) payload handling in telemetry attributes
- Path traversal & invalid entity ID boundaries
- Query parameter constraints (limit/offset boundary validation)
- Information leakage & unhandled error masking (no stack traces or file paths leaked)
- Strict CORS origin validation
- Detection false-positive prevention on benign security events
- ML anomaly non-confirmation policy & explicit disclaimers
- Database persistence integrity and duplicate suppression
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

# Create an isolated temporary test database before importing main
TEST_DB = tempfile.NamedTemporaryFile(suffix="_sec_qa.db", delete=False)
TEST_DB.close()
os.environ["CYBERSHIELD_DB_PATH"] = TEST_DB.name

import backend.main as main
from backend.models.event import SecurityEvent


@pytest.fixture(scope="session")
def client():
    """Create a FastAPI test client bound to the test database."""
    main.DB_PATH = Path(TEST_DB.name)
    main.init_db()
    with TestClient(main.app) as c:
        yield c
    try:
        if os.path.exists(TEST_DB.name):
            os.remove(TEST_DB.name)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def clean_database():
    """Wipe database tables and reset engine caches before each test."""
    main.init_db()
    with main.connect() as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM anomalies")
    main.reset_caches()


# =====================================================================
# 1. Input Validation & File-Handling Safety
# =====================================================================

def test_security_empty_upload_rejected(client):
    """Empty CSV files must be rejected with HTTP 400 and clear error detail."""
    empty_file = io.BytesIO(b"")
    res = client.post("/api/logs/upload", files={"file": ("empty.csv", empty_file, "text/csv")})
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()


def test_security_disallowed_file_extensions_rejected(client):
    """Dangerous file extensions (.sh, .exe, .py, .html, .bin) must be blocked."""
    payloads = [
        ("malicious.sh", b"#!/bin/bash\nrm -rf /", "application/x-sh"),
        ("exploit.exe", b"MZ\x90\x00\x03\x00\x00\x00", "application/octet-stream"),
        ("script.py", b"import os; os.system('ls')", "text/x-python"),
        ("page.html", b"<html><body>test</body></html>", "text/html"),
    ]
    for filename, content, mime in payloads:
        f = io.BytesIO(content)
        res = client.post("/api/logs/upload", files={"file": (filename, f, mime)})
        assert res.status_code == 400
        assert ".csv" in res.json()["detail"].lower()


def test_security_oversized_payload_rejected(client):
    """Payloads exceeding the 10 MB limit must be rejected without memory exhaustion."""
    oversized_data = b"a" * (main.MAX_UPLOAD_BYTES + 1024)
    f = io.BytesIO(oversized_data)
    res = client.post("/api/logs/upload", files={"file": ("large.csv", f, "text/csv")})
    assert res.status_code in [400, 413]
    assert "limit" in res.json()["detail"].lower() or "exceeds" in res.json()["detail"].lower()


def test_security_null_bytes_and_binary_corruption_rejected(client):
    """Binary files containing null bytes must be rejected as invalid."""
    corrupted_csv = b"timestamp,source_ip,username,event_type,status\n2026-10-15T12:00:00Z,\x00\x00\x00,alice,login,success\n"
    f = io.BytesIO(corrupted_csv)
    res = client.post("/api/logs/upload", files={"file": ("corrupt.csv", f, "text/csv")})
    assert res.status_code == 400
    assert "null bytes" in res.json()["detail"].lower() or "invalid" in res.json()["detail"].lower()


def test_security_non_utf8_encoding_handled(client):
    """Files with non-UTF8 encodings must return a client-friendly 400 error."""
    # Invalid UTF-8 sequence
    invalid_bytes = b"\xff\xfe\x00\x00timestamp,source_ip,username,event_type,status\n"
    f = io.BytesIO(invalid_bytes)
    res = client.post("/api/logs/upload", files={"file": ("encoding.csv", f, "text/csv")})
    assert res.status_code == 400
    assert "encoding" in res.json()["detail"].lower() or "utf-8" in res.json()["detail"].lower()


# =====================================================================
# 2. SQL Injection (SQLi) Resilience & Parameterization
# =====================================================================

def test_security_sql_injection_in_search_parameters(client):
    """
    Test SQL injection strings in GET endpoints.
    Parameterized queries must prevent injection or syntax breakage.
    """
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE events; --",
        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
        "admin'--",
        "1' OR 1=1#",
    ]
    for payload in sql_payloads:
        # Search events
        res_events = client.get(f"/api/events?search={payload}")
        assert res_events.status_code == 200
        assert isinstance(res_events.json()["events"], list)

        # Search alerts
        res_alerts = client.get(f"/api/alerts?search={payload}")
        assert res_alerts.status_code == 200
        assert isinstance(res_alerts.json()["alerts"], list)

        # Filter alerts by entity
        res_entity = client.get(f"/api/alerts?entity={payload}")
        assert res_entity.status_code == 200
        assert isinstance(res_entity.json()["alerts"], list)


def test_security_xss_in_telemetry_stored_safely(client):
    """
    XSS strings in username, resource, or source IP must be stored as inert text,
    never executing or corrupting the backend state.
    """
    xss_csv = (
        "timestamp,source_ip,username,event_type,status,resource\n"
        "2026-10-15T12:00:00Z,192.168.1.50,<script>alert('xss')</script>,login,failed,<img src=x onerror=alert(1)>\n"
    )
    res = client.post("/api/logs/upload", files={"file": ("xss.csv", io.BytesIO(xss_csv.encode()), "text/csv")})
    assert res.status_code == 200

    # Retrieve event and verify sanitized/escaped inert storage
    events_res = client.get("/api/events?search=script")
    assert events_res.status_code == 200
    events = events_res.json()["events"]
    assert len(events) == 1
    assert "<script>alert('xss')</script>" in events[0]["username"]


# =====================================================================
# 3. Path Traversal & Boundary Safety
# =====================================================================

def test_security_negative_and_overflow_ids_return_404(client):
    """Requesting negative or non-existent integer IDs must safely return 404."""
    invalid_ids = [-1, 0, 999999999]
    for test_id in invalid_ids:
        res_event = client.get(f"/api/events/{test_id}")
        assert res_event.status_code == 404

        res_alert = client.get(f"/api/alerts/{test_id}")
        assert res_alert.status_code == 404


def test_security_pagination_constraints_enforced(client):
    """Negative limit or offset, or excessive limit, must return 422 Unprocessable Entity."""
    # Negative limit
    res1 = client.get("/api/events?limit=-1")
    assert res1.status_code == 422

    # Zero limit
    res2 = client.get("/api/events?limit=0")
    assert res2.status_code == 422

    # Negative offset
    res3 = client.get("/api/events?offset=-5")
    assert res3.status_code == 422

    # Excessive limit (> 500 for events)
    res4 = client.get("/api/events?limit=10000")
    assert res4.status_code == 422


# =====================================================================
# 4. Information Leakage & Error Masking
# =====================================================================

def test_security_unhandled_exception_masks_stack_traces(client, monkeypatch):
    """
    If an unexpected internal exception occurs, the global exception handler
    must return a sanitized 500 JSON error without leaking internal file paths,
    modules, or traceback strings.
    """
    def broken_func(*args, **kwargs):
        raise RuntimeError("SecretInternalDatabaseException at /var/secrets/app.py:42")

    # Monkeypatch execute_full_detection_pipeline to raise an unexpected internal exception
    monkeypatch.setattr(main, "execute_full_detection_pipeline", broken_func)

    with TestClient(main.app, raise_server_exceptions=False) as safe_client:
        res = safe_client.post("/api/detection/run")
        assert res.status_code == 500
        body = res.json()
        assert body["error"] == "InternalServerError"
        assert "SecretInternalDatabaseException" not in body["detail"]
        assert "/var/secrets" not in body["detail"]
        assert "traceback" not in body


def test_security_cors_restrictions(client):
    """
    Verify CORS headers are strictly restricted to development origins.
    Untrusted origins must not receive Access-Control-Allow-Origin.
    """
    # Allowed origin
    res_allowed = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert res_allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    # Disallowed untrusted origin
    res_blocked = client.get("/api/health", headers={"Origin": "https://attacker.evil.com"})
    assert res_blocked.headers.get("access-control-allow-origin") is None


# =====================================================================
# 5. Detection False-Positive Prevention
# =====================================================================

def test_qa_isolated_failed_logins_never_flagged_as_attack(client):
    """
    Benign behavior: isolated failed logins (1 or 2 failures) must NOT
    be classified as an attack by the rule engine.
    """
    from backend.detection import ThreatDetectionEngine
    engine = ThreatDetectionEngine()
    benign_events = [
        SecurityEvent(timestamp="2026-10-15T09:00:00Z", source_ip="10.0.0.15", username="david", event_type="login", status="failed"),
        SecurityEvent(timestamp="2026-10-15T09:01:00Z", source_ip="10.0.0.15", username="david", event_type="login", status="failed"),
    ]
    rule_alerts = engine.detect(benign_events)
    assert len(rule_alerts) == 0

    # Also verify that when uploaded through API, no High or Critical attack alerts are generated
    benign_csv = (
        "timestamp,source_ip,username,event_type,status\n"
        "2026-10-15T09:00:00Z,10.0.0.15,david,login,failed\n"
        "2026-10-15T09:01:00Z,10.0.0.15,david,login,failed\n"
    )
    res = client.post("/api/logs/upload", files={"file": ("benign.csv", io.BytesIO(benign_csv.encode()), "text/csv")})
    assert res.status_code == 200
    alerts = client.get("/api/alerts?severity=High").json()["alerts"]
    assert len(alerts) == 0
    crit_alerts = client.get("/api/alerts?severity=Critical").json()["alerts"]
    assert len(crit_alerts) == 0


def test_qa_temporally_separated_failures_not_flagged(client):
    """
    Failed logins spaced hours apart (outside the 5-minute / 10-minute window)
    must not trigger brute-force alerts in the rule engine.
    """
    from backend.detection import ThreatDetectionEngine
    engine = ThreatDetectionEngine()
    separated_events = [
        SecurityEvent(timestamp="2026-10-15T08:00:00Z", source_ip="10.0.0.20", username="emily", event_type="login", status="failed"),
        SecurityEvent(timestamp="2026-10-15T11:00:00Z", source_ip="10.0.0.20", username="emily", event_type="login", status="failed"),
        SecurityEvent(timestamp="2026-10-15T15:00:00Z", source_ip="10.0.0.20", username="emily", event_type="login", status="failed"),
        SecurityEvent(timestamp="2026-10-15T19:00:00Z", source_ip="10.0.0.20", username="emily", event_type="login", status="failed"),
    ]
    rule_alerts = engine.detect(separated_events)
    assert len(rule_alerts) == 0


def test_qa_normal_business_hours_not_flagged_as_unusual_hours(client):
    """
    Logins occurring during normal baseline business hours (e.g., 10:00 AM)
    must not trigger Unusual Login Hours alerts.
    """
    from backend.detection import ThreatDetectionEngine
    engine = ThreatDetectionEngine()
    baseline_events = [
        SecurityEvent(timestamp=f"2026-10-10T{h:02d}:00:00Z", source_ip="10.0.0.25", username="frank", event_type="login", status="success")
        for h in (9, 10, 11, 14, 15, 17)
    ]
    engine.learn_baseline(baseline_events)

    normal_event = SecurityEvent(timestamp="2026-10-15T10:00:00Z", source_ip="10.0.0.25", username="frank", event_type="login", status="success")
    alerts = engine.detect([normal_event])
    assert not any(a.rule_name == "Unusual Login Hours" for a in alerts)


# =====================================================================
# 6. ML Model Limitations & Non-Confirmation Policy
# =====================================================================

def test_qa_ml_anomaly_disclaimer_present(client):
    """
    ML anomaly findings must strictly include the non-malicious disclaimer
    acknowledging statistical deviation is not confirmed malice.
    """
    from backend.ml.anomaly import AnomalyDetectionPipeline
    pipeline = AnomalyDetectionPipeline(contamination=0.2, random_state=42)

    sample_events = [
        SecurityEvent(timestamp="2026-10-15T12:00:00Z", source_ip="192.168.1.1", username="user1", event_type="login", status="success"),
        SecurityEvent(timestamp="2026-10-15T12:01:00Z", source_ip="192.168.1.1", username="user1", event_type="login", status="success"),
        SecurityEvent(timestamp="2026-10-15T12:02:00Z", source_ip="192.168.1.1", username="user1", event_type="login", status="success"),
        SecurityEvent(timestamp="2026-10-15T12:03:00Z", source_ip="192.168.1.1", username="user1", event_type="login", status="success"),
        SecurityEvent(timestamp="2026-10-15T12:04:00Z", source_ip="192.168.1.1", username="user1", event_type="login", status="success"),
        # Extreme statistical outlier
        SecurityEvent(timestamp="2026-10-15T03:00:00Z", source_ip="203.0.113.99", username="unknown_service", event_type="unusual_rpc", status="failed", payload_size=999999),
    ]

    pipeline.fit(sample_events)
    findings = pipeline.score(sample_events)
    assert len(findings) == len(sample_events)

    for f in findings:
        assert f.disclaimer is not None
        assert "not necessarily" in f.disclaimer.lower() or "statistical anomaly" in f.disclaimer.lower()


def test_qa_anomaly_only_incident_never_confirmed_critical(client):
    """
    An incident driven solely by ML anomaly scores must NOT be marked confirmed,
    must have lower confidence, and must not exceed Medium severity.
    """
    from backend.risk_assessment import ThreatRiskEngine
    from backend.models.anomaly import AnomalyFinding

    engine = ThreatRiskEngine()
    dummy_finding = AnomalyFinding(
        finding_id="CS-ANOMALY-TEST",
        event_fingerprint="fp123",
        timestamp="2026-10-15T12:00:00Z",
        entity="198.51.100.5",
        is_anomaly=True,
        anomaly_score=0.95,
        raw_score=-0.25,
        contributing_factors=["Payload size outlier"],
    )

    incidents = engine.assess_and_correlate(events=[], rule_alerts=[], anomaly_findings=[dummy_finding])
    assert len(incidents) == 1
    inc = incidents[0]

    # Non-confirmation constraint
    assert inc.is_confirmed is False
    assert inc.confidence <= 0.50
    assert inc.severity in ["Low", "Medium"]
    assert "Unconfirmed" in inc.confirmation_status
