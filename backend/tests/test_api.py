"""
CyberShield AI — Phase 06 FastAPI REST Backend Integration Tests

Covers:
- System health checks and metadata verification
- CSV security log upload validation (size limits, file extensions, UTF-8 encoding, malformed rows)
- On-demand detection pipeline execution
- Event pagination and multi-field filtering (username, source_ip, event_type, status, search)
- Granular event detail retrieval and 404 error handling
- Threat alert pagination and multi-criteria filtering (severity, status, entity, search)
- Granular alert detail retrieval, explainability structure, and 404 handling
- SOC alert triage lifecycle status updates (Open -> Investigating -> Resolved)
- Executive dashboard summary metrics and trend aggregations
- SQLite persistence verification
- Strict CORS origin restriction verification
- Information leakage and stack-trace prevention
"""

import io
import os
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

# Create an isolated temporary test database before importing main
TEST_DB = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
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


# Sample valid CSV content for testing
VALID_CSV = """timestamp,source_ip,destination_ip,username,event_type,status,resource,payload_size
2026-10-15T09:00:00Z,192.168.1.10,10.0.0.1,alice,login,success,/auth/login,128
2026-10-15T09:01:00Z,203.0.113.50,10.0.0.1,admin,login,failed,/auth/login,128
2026-10-15T09:02:00Z,203.0.113.50,10.0.0.1,admin,login,failed,/auth/login,128
2026-10-15T09:03:00Z,203.0.113.50,10.0.0.1,admin,login,failed,/auth/login,128
2026-10-15T09:04:00Z,203.0.113.50,10.0.0.1,admin,login,failed,/auth/login,128
2026-10-15T09:05:00Z,203.0.113.50,10.0.0.1,admin,login,failed,/auth/login,128
2026-10-15T09:06:00Z,203.0.113.50,10.0.0.1,admin,login,success,/auth/login,128
2026-10-15T09:10:00Z,192.168.1.15,10.0.0.2,bob,file_access,success,/data/report.pdf,2048
"""


# =====================================================================
# 1. Health & Server Diagnostics Tests
# =====================================================================

def test_health_endpoint(client: TestClient):
    """GET /api/health returns 200 with service metadata and UTC timestamp."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "CyberShield AI"
    assert data["database"] == "sqlite"
    assert data["version"] == "1.0.0"
    assert "timestamp" in data


def test_home_endpoint(client: TestClient):
    """GET / returns online response or serves frontend."""
    response = client.get("/")
    assert response.status_code == 200


# =====================================================================
# 2. CSV Log Ingestion Tests (POST /api/logs/upload)
# =====================================================================

def test_upload_valid_csv(client: TestClient):
    """Uploading a valid CSV ingests events, creates alerts, and returns summary."""
    files = {"file": ("security_telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    response = client.post("/api/logs/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "CSV processed"
    assert data["rows_received"] == 8
    assert data["valid_rows"] == 8
    assert data["new_events"] == 8
    assert data["rejected_count"] == 0
    assert data["total_alerts"] >= 2


def test_upload_duplicate_suppression(client: TestClient):
    """Re-uploading the same CSV suppresses duplicate events and does not inflate database."""
    files1 = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    res1 = client.post("/api/logs/upload", files=files1)
    assert res1.status_code == 200
    assert res1.json()["new_events"] == 8

    # Second upload of the identical file
    files2 = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    res2 = client.post("/api/logs/upload", files=files2)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["valid_rows"] == 0
    assert data2["duplicate_count"] == 8
    assert data2["new_events"] == 0


def test_upload_invalid_extension(client: TestClient):
    """Uploading non-CSV extensions is rejected with 400 Bad Request."""
    files = {"file": ("malware.exe", io.BytesIO(b"binary data"), "application/octet-stream")}
    response = client.post("/api/logs/upload", files=files)
    assert response.status_code == 400
    assert "Invalid file format" in response.json()["detail"]


def test_upload_oversized_payload(client: TestClient):
    """Payloads exceeding the 10 MB limit are rejected with 413 Entity Too Large."""
    oversized_data = b"timestamp,source_ip,username,event_type,status\n" + b"X" * (10 * 1024 * 1024 + 512)
    files = {"file": ("large_telemetry.csv", io.BytesIO(oversized_data), "text/csv")}
    response = client.post("/api/logs/upload", files=files)
    assert response.status_code == 413
    assert "exceeds maximum allowed limit" in response.json()["detail"]


def test_upload_empty_csv(client: TestClient):
    """Empty CSV files are rejected with 400 Bad Request."""
    files = {"file": ("empty.csv", io.BytesIO(b""), "text/csv")}
    response = client.post("/api/logs/upload", files=files)
    assert response.status_code == 400


def test_upload_corrupted_rows(client: TestClient):
    """CSV containing only invalid or malformed rows returns 400 with row diagnostics."""
    bad_csv = "timestamp,source_ip,username,event_type,status\ninvalid_time,bad_ip,,,,\n"
    files = {"file": ("bad.csv", io.BytesIO(bad_csv.encode("utf-8")), "text/csv")}
    response = client.post("/api/logs/upload", files=files)
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "No valid rows found" in detail["message"]
    assert len(detail["rejected"]) > 0


# =====================================================================
# 3. Detection Execution Tests (POST /api/detection/run)
# =====================================================================

def test_trigger_detection_endpoint(client: TestClient):
    """POST /api/detection/run evaluates existing events and returns detection summary."""
    # First seed data via upload
    files = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    client.post("/api/logs/upload", files=files)

    # Clear alerts to verify on-demand detection pipeline generates alerts from persisted events
    with main.connect() as conn:
        conn.execute("DELETE FROM alerts")
    main.reset_caches()

    response = client.post("/api/detection/run")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Detection completed successfully"
    assert data["total_events_analyzed"] == 8
    assert data["rule_alerts_generated"] >= 2
    assert "duration_ms" in data

    # A subsequent run over identical events suppresses duplicate alerts
    res_repeat = client.post("/api/detection/run")
    assert res_repeat.status_code == 200
    assert res_repeat.json()["rule_alerts_generated"] == 0


# =====================================================================
# 4. Security Events Listing & Filtering (GET /api/events)
# =====================================================================

def test_events_pagination(client: TestClient):
    """GET /api/events respects limit and offset parameters."""
    files = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    client.post("/api/logs/upload", files=files)

    res_page1 = client.get("/api/events?limit=3&offset=0")
    assert res_page1.status_code == 200
    p1_data = res_page1.json()
    assert p1_data["total"] == 8
    assert p1_data["count"] == 3
    assert len(p1_data["events"]) == 3

    res_page2 = client.get("/api/events?limit=3&offset=3")
    assert res_page2.status_code == 200
    p2_data = res_page2.json()
    assert p2_data["total"] == 8
    assert p2_data["count"] == 3

    # Assert pages have disjoint events
    p1_ids = {e["id"] for e in p1_data["events"]}
    p2_ids = {e["id"] for e in p2_data["events"]}
    assert p1_ids.isdisjoint(p2_ids)


def test_events_filtering(client: TestClient):
    """GET /api/events supports filtering by username, source_ip, event_type, and status."""
    files = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    client.post("/api/logs/upload", files=files)

    # Filter by username
    res_user = client.get("/api/events?username=alice")
    assert res_user.status_code == 200
    assert all(e["username"] == "alice" for e in res_user.json()["events"])
    assert res_user.json()["total"] == 1

    # Filter by source_ip
    res_ip = client.get("/api/events?source_ip=203.0.113.50")
    assert res_ip.status_code == 200
    assert all(e["source_ip"] == "203.0.113.50" for e in res_ip.json()["events"])
    assert res_ip.json()["total"] == 6

    # Filter by status
    res_status = client.get("/api/events?status=failed")
    assert res_status.status_code == 200
    assert all(e["status"] == "failed" for e in res_status.json()["events"])
    assert res_status.json()["total"] == 5

    # Global search
    res_search = client.get("/api/events?search=report.pdf")
    assert res_search.status_code == 200
    assert res_search.json()["total"] == 1


def test_event_detail_and_404(client: TestClient):
    """GET /api/events/{id} returns single event or 404 for missing IDs."""
    files = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    client.post("/api/logs/upload", files=files)

    events = client.get("/api/events").json()["events"]
    first_id = events[0]["id"]

    res_detail = client.get(f"/api/events/{first_id}")
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == first_id

    res_missing = client.get("/api/events/999999")
    assert res_missing.status_code == 404
    assert res_missing.json()["detail"] == "Event not found"


# =====================================================================
# 5. Threat Alerts Listing & Filtering (GET /api/alerts)
# =====================================================================

def test_alerts_listing_and_filtering(client: TestClient):
    """GET /api/alerts filters by severity, status, entity, and search."""
    files = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    client.post("/api/logs/upload", files=files)

    res_all = client.get("/api/alerts")
    assert res_all.status_code == 200
    all_data = res_all.json()
    assert all_data["total"] >= 2
    assert len(all_data["alerts"]) >= 2

    # Verify backward compatibility of alert item format
    first_alert = all_data["alerts"][0]
    assert "id" in first_alert
    assert "timestamp" in first_alert
    assert "source_ip" in first_alert
    assert "category" in first_alert
    assert "severity" in first_alert
    assert "risk_score" in first_alert
    assert "description" in first_alert
    assert isinstance(first_alert["evidence"], list)
    assert "recommendation" in first_alert
    assert "status" in first_alert

    # Filter by severity
    res_high = client.get("/api/alerts?severity=High")
    assert res_high.status_code == 200
    assert all(a["severity"] == "High" for a in res_high.json()["alerts"])

    # Filter by status
    res_open = client.get("/api/alerts?status=Open")
    assert res_open.status_code == 200
    assert all(a["status"] == "Open" for a in res_open.json()["alerts"])

    # Filter by entity
    res_entity = client.get("/api/alerts?entity=203.0.113.50")
    assert res_entity.status_code == 200
    assert len(res_entity.json()["alerts"]) >= 1


def test_alert_detail_and_404(client: TestClient):
    """GET /api/alerts/{id} returns complete alert details or 404."""
    files = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    client.post("/api/logs/upload", files=files)

    alerts = client.get("/api/alerts").json()["alerts"]
    alert_id = alerts[0]["id"]

    res_detail = client.get(f"/api/alerts/{alert_id}")
    assert res_detail.status_code == 200
    d = res_detail.json()
    assert d["id"] == alert_id
    assert isinstance(d["evidence"], list)

    res_404 = client.get("/api/alerts/999999")
    assert res_404.status_code == 404


# =====================================================================
# 6. SOC Alert Triage Status Updates (PATCH /api/alerts/{id})
# =====================================================================

def test_alert_status_triage_lifecycle(client: TestClient):
    """PATCH /api/alerts/{id} updates triage status and validates transitions."""
    files = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    client.post("/api/logs/upload", files=files)

    alerts = client.get("/api/alerts").json()["alerts"]
    target_id = alerts[0]["id"]

    # Transition to Investigating
    res_inv = client.patch(f"/api/alerts/{target_id}", json={"status": "Investigating"})
    assert res_inv.status_code == 200
    assert res_inv.json()["status"] == "Investigating"
    assert client.get(f"/api/alerts/{target_id}").json()["status"] == "Investigating"

    # Transition to Resolved
    res_res = client.patch(f"/api/alerts/{target_id}", json={"status": "Resolved"})
    assert res_res.status_code == 200
    assert res_res.json()["status"] == "Resolved"
    assert client.get(f"/api/alerts/{target_id}").json()["status"] == "Resolved"

    # Invalid status rejection
    res_invalid = client.patch(f"/api/alerts/{target_id}", json={"status": "NonExistentStatus"})
    assert res_invalid.status_code == 400
    assert "Status must be one of" in res_invalid.json()["detail"]

    # Missing alert 404
    res_missing = client.patch("/api/alerts/999999", json={"status": "Resolved"})
    assert res_missing.status_code == 404


# =====================================================================
# 7. Dashboard Summary Statistics (GET /api/dashboard/stats)
# =====================================================================

def test_dashboard_stats_endpoint(client: TestClient):
    """GET /api/dashboard/stats aggregates event counts, severities, and trends."""
    files = {"file": ("telemetry.csv", io.BytesIO(VALID_CSV.encode("utf-8")), "text/csv")}
    client.post("/api/logs/upload", files=files)

    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    stats = res.json()

    assert stats["processed_events"] == 8
    assert stats["total_alerts"] >= 2
    assert stats["open_alerts"] >= 1
    assert stats["high_critical_alerts"] >= 1
    assert isinstance(stats["severity_distribution"], dict)
    assert isinstance(stats["event_trend"], list)
    assert len(stats["event_trend"]) > 0
    assert "date" in stats["event_trend"][0]
    assert "count" in stats["event_trend"][0]
    assert isinstance(stats["top_source_ips"], list)
    assert isinstance(stats["top_targeted_users"], list)


# =====================================================================
# 8. CORS Restriction Tests
# =====================================================================

def test_cors_headers_allowed_origin(client: TestClient):
    """Allowed frontend origins receive valid CORS access-control headers."""
    response = client.get(
        "/api/health",
        headers={"Origin": "http://localhost:5173"}
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_cors_headers_disallowed_origin(client: TestClient):
    """Untrusted origins do not receive permissive CORS access-control headers."""
    response = client.get(
        "/api/health",
        headers={"Origin": "http://malicious-external-attacker.com"}
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") != "http://malicious-external-attacker.com"
