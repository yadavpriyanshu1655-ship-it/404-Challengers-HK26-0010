"""
CyberShield AI — Phase 08 End-to-End Frontend and Backend Integration Tests
Official Problem: ABCS-01 — Intelligent Cyber Threat Detection
Team: 404 Challengers

Tests the complete 8-step integration workflow:
1. Upload sample CSV telemetry.
2. Validate and ingest records with duplicate detection.
3. Execute rule-based detection and ML anomaly scoring.
4. Correlate findings and calculate risk severity.
5. Persist events and alerts in SQLite.
6. Verify dashboard executive metrics reflect backend responses.
7. Open alert detail and inspect evidence, explanations, and safe defensive steps.
8. Filter, search, and manage alert triage lifecycle.
Also verifies deduplication prevention, error handling, and frontend static asset serving.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

# Create an isolated temporary test database before importing main
TEST_DB = tempfile.NamedTemporaryFile(suffix="_e2e.db", delete=False)
TEST_DB.close()
os.environ["CYBERSHIELD_DB_PATH"] = TEST_DB.name

import backend.main as main
from backend.db.database import get_db_connection


@pytest.fixture(scope="session")
def client():
    """Create a FastAPI test client bound to the isolated test database."""
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


def test_e2e_full_workflow_upload_to_inspection(client):
    """
    Complete 8-step SOC workflow:
    1. Verify system health.
    2. Upload sample CSV telemetry.
    3. Validate ingestion counts and schema.
    4. Verify detection and ML anomaly scoring ran.
    5. Verify SQLite persistence.
    6. Verify dashboard metrics reflect ingested data.
    7. Inspect alert detail: evidence, observed vs threshold, explanation, and defensive recommendations.
    8. Filter by severity and search by keyword.
    9. Update alert triage status and verify metrics update.
    """
    # Step 1: Health check
    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert health_data["status"] in ["ok", "online"]
    assert "cybershield" in health_data["service"].lower()

    # Step 2: Upload sample CSV telemetry (using backend/data/sample_logs.csv)
    sample_path = Path(__file__).resolve().parent.parent / "data" / "sample_logs.csv"
    assert sample_path.exists(), f"Sample CSV file not found at {sample_path}"

    with open(sample_path, "rb") as f:
        upload_res = client.post(
            "/api/logs/upload",
            files={"file": ("sample_logs.csv", f, "text/csv")},
        )

    # Step 3: Validate ingestion counts
    assert upload_res.status_code == 200
    upload_data = upload_res.json()
    assert upload_data["success"] is True
    assert upload_data["rows_received"] > 0
    assert upload_data["valid_rows"] > 0
    assert upload_data["new_events"] == upload_data["valid_rows"]
    assert upload_data["duplicate_count"] == 0

    # Step 4: Verify detection execution ran and produced alerts
    assert upload_data["total_alerts"] > 0

    # Step 5: Verify persistence in SQLite
    with get_db_connection(main.DB_PATH) as conn:
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    assert event_count == upload_data["valid_rows"]
    assert alert_count == upload_data["total_alerts"]

    # Step 6: Verify dashboard summary metrics reflect backend state
    stats_res = client.get("/api/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["processed_events"] == event_count
    assert stats["total_alerts"] == alert_count
    assert stats["open_alerts"] == alert_count  # All alerts start as Open
    assert sum(stats["severity_distribution"].values()) == alert_count
    assert stats["status_distribution"].get("Open", 0) == alert_count
    assert len(stats["event_trend"]) > 0
    assert len(stats["top_source_ips"]) > 0

    # Step 7: Open alert list and inspect highest severity alert detail
    alerts_res = client.get("/api/alerts?limit=10")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()
    assert len(alerts_data["alerts"]) > 0

    first_alert = alerts_data["alerts"][0]
    alert_id = first_alert["id"]

    # Fetch granular alert detail
    detail_res = client.get(f"/api/alerts/{alert_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()

    assert detail["id"] == alert_id
    assert detail["severity"] in ["Low", "Medium", "High", "Critical"]
    assert detail["status"] == "Open"
    assert detail["description"] is not None and len(detail["description"]) > 0
    assert detail["evidence"] is not None and len(detail["evidence"]) > 0
    assert detail["recommendation"] is not None and len(detail["recommendation"]) > 0
    assert isinstance(detail["related_event_ids"], list)
    assert detail["risk_score"] >= 0

    # Step 8: Filter and search results
    # Search by source IP or username
    search_target = detail["source_ip"]
    filtered_res = client.get(f"/api/alerts?search={search_target}")
    assert filtered_res.status_code == 200
    search_results = filtered_res.json()["alerts"]
    assert len(search_results) >= 1
    assert any(a["source_ip"] == search_target for a in search_results)

    # Filter by severity
    severity_target = detail["severity"]
    sev_res = client.get(f"/api/alerts?severity={severity_target}")
    assert sev_res.status_code == 200
    for a in sev_res.json()["alerts"]:
        assert a["severity"] == severity_target

    # Step 9: Alert triage lifecycle management (Open -> Investigating -> Resolved)
    patch_res = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "Investigating"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Investigating"

    # Confirm dashboard metrics updated
    stats_after_patch = client.get("/api/dashboard/stats").json()
    assert stats_after_patch["open_alerts"] == alert_count - 1
    assert stats_after_patch["status_distribution"].get("Investigating", 0) == 1

    # Resolve alert
    resolve_res = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "Resolved"},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "Resolved"


def test_e2e_deduplication_prevention(client):
    """
    Verify that uploading the exact same telemetry twice detects duplicates,
    does not insert duplicate event records, and does not create duplicate alerts.
    """
    sample_path = Path(__file__).resolve().parent.parent / "data" / "sample_logs.csv"

    # First upload
    with open(sample_path, "rb") as f:
        res1 = client.post("/api/logs/upload", files={"file": ("sample.csv", f, "text/csv")})
    assert res1.status_code == 200
    data1 = res1.json()
    initial_valid = data1["valid_rows"]
    initial_alerts = data1["total_alerts"]
    assert data1["new_events"] == initial_valid
    assert data1["duplicate_count"] == 0

    # Second upload of the identical file
    with open(sample_path, "rb") as f:
        res2 = client.post("/api/logs/upload", files={"file": ("sample.csv", f, "text/csv")})
    assert res2.status_code == 200
    data2 = res2.json()

    # All rows should be recognized as duplicates
    assert data2["duplicate_count"] == initial_valid
    assert data2["new_events"] == 0
    # Alerts should not have duplicated
    assert data2["total_alerts"] == initial_alerts


def test_e2e_invalid_upload_rejections(client):
    """
    Verify that invalid file uploads return appropriate HTTP 400 errors with clear explanations.
    """
    # 1. Empty file
    empty_csv = io.BytesIO(b"")
    res_empty = client.post("/api/logs/upload", files={"file": ("empty.csv", empty_csv, "text/csv")})
    assert res_empty.status_code == 400
    assert "empty" in res_empty.json()["detail"].lower()

    # 2. Missing required schema columns
    invalid_csv = io.BytesIO(b"timestamp,source_ip\n2026-10-15T12:00:00Z,192.168.1.10\n")
    res_invalid = client.post("/api/logs/upload", files={"file": ("bad_schema.csv", invalid_csv, "text/csv")})
    assert res_invalid.status_code == 400
    assert "missing" in res_invalid.json()["detail"].lower()

    # 3. Non-CSV file extension
    text_file = io.BytesIO(b"random text file content")
    res_ext = client.post("/api/logs/upload", files={"file": ("malware.exe", text_file, "application/octet-stream")})
    assert res_ext.status_code == 400
    assert ".csv" in res_ext.json()["detail"].lower()


def test_e2e_frontend_static_serving(client):
    """
    Verify that the FastAPI root endpoint serves the compiled React dashboard
    when frontend/dist exists.
    """
    res = client.get("/")
    assert res.status_code == 200
    # If frontend/dist/index.html is served, it contains HTML doctype or title
    content = res.text
    assert "<!doctype html" in content.lower() or "<html" in content.lower() or "cybershield" in content.lower()


def test_e2e_demo_lifecycle_reset_and_sample(client):
    """
    Verify demo reset and benchmark loading endpoints.
    """
    # Load sample via demo endpoint
    sample_res = client.post("/api/demo/sample")
    assert sample_res.status_code == 200
    sample_data = sample_res.json()
    assert sample_data["valid_rows"] > 0
    assert sample_data["total_alerts"] > 0

    # Verify data is in DB
    stats = client.get("/api/dashboard/stats").json()
    assert stats["processed_events"] > 0
    assert stats["total_alerts"] > 0

    # Reset demo
    reset_res = client.post("/api/demo/reset")
    assert reset_res.status_code == 200
    assert reset_res.json()["reset"] is True

    # Verify DB is cleared
    stats_empty = client.get("/api/dashboard/stats").json()
    assert stats_empty["processed_events"] == 0
    assert stats_empty["total_alerts"] == 0
    assert stats_empty["open_alerts"] == 0
