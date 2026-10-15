"""
CyberShield AI — FastAPI REST Backend
Official Problem: ABCS-01 — Intelligent Cyber Threat Detection
Team: 404 Challengers

Exposes REST APIs for:
- System health checks and telemetry diagnostics
- CSV security log ingestion with robust validation and schema normalization
- Rule-based detection and machine-learning anomaly scoring execution
- Correlated threat alert and incident listing with multi-field filtering and pagination
- Alert status triage lifecycle management (Open, Investigating, Resolved, Dismissed)
- Executive dashboard summary metrics and time-series event trends
- Granular event and alert incident detail inspection
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import logging
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.db.database import (
    create_connection,
    format_alert_dict,
    format_event_dict,
    get_db_connection,
    get_db_path,
    init_db as db_init,
    insert_anomalies,
    insert_events,
    insert_or_update_alert,
)
from backend.detection import ThreatDetectionEngine
from backend.ingestion import (
    EmptyFileError,
    IngestionError,
    InvalidFileError,
    MissingColumnError,
    SecurityLogIngestion,
)
from backend.ml.anomaly import AnomalyDetectionPipeline
from backend.models.alert import ThreatAlert
from backend.models.event import IngestionResult, SecurityEvent
from backend.models.risk import CorrelatedIncident
from backend.risk_assessment import ThreatRiskEngine
from backend.schemas.api import (
    AlertListResponse,
    AlertResponse,
    AlertStatusUpdate,
    DashboardStatsResponse,
    DetectionRunResponse,
    ErrorDetail,
    EventListResponse,
    HealthResponse,
    RejectedRowSummary,
    SecurityEventSchema,
    UploadLogsResponse,
)

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cybershield.api")

# Directory & DB configuration
ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("CYBERSHIELD_DB_PATH", str(ROOT / "cybershield.db")))
WEB_DIR = ROOT / "frontend"
MODELS_DIR = ROOT / "backend" / "models"
DATA_DIR = ROOT / "backend" / "data"
MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"

# Maximum CSV upload size (10 MB)
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

# Allowed CORS origins for frontend development
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Rule to Category name mapping for clear, explainable findings
RULE_CATEGORY_MAP = {
    "Repeated Failed Logins": "Brute-force login attempts",
    "Success Following Repeated Failures": "Success after repeated failures",
    "High Login Frequency": "High login frequency burst",
    "Unusual Login Hours": "Unusual login hours",
    "Suspicious Behavioral Shift": "Suspicious behavioral shift",
}

# Initialize FastAPI application
app = FastAPI(
    title="CyberShield AI REST API",
    version="1.0.0",
    description="Intelligent Cyber Threat Detection & Incident Correlation Backend (ABCS-01)",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Restrict CORS specifically to trusted frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount frontend assets if directory exists (prefer compiled React dist)
dist_dir = WEB_DIR / "dist"
if (dist_dir / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(dist_dir / "assets")), name="assets")
elif (WEB_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(WEB_DIR / "assets")), name="assets")


# =====================================================================
# Database Helpers & Initialization
# =====================================================================

def connect() -> sqlite3.Connection:
    """Return an active SQLite connection configured with WAL and row factory."""
    return create_connection(DB_PATH)


# =====================================================================
# Detection Engines & Machine Learning Lifecycle
# =====================================================================

ingestion_engine = SecurityLogIngestion()
detection_engine = ThreatDetectionEngine()
risk_engine = ThreatRiskEngine()
_ml_pipeline: Optional[AnomalyDetectionPipeline] = None


def reset_caches() -> None:
    """Reset in-memory deduplication and alert caches."""
    ingestion_engine.reset_deduplication()
    detection_engine.reset_alert_cache()
    risk_engine.reset()


def init_db() -> None:
    """Initialize SQLite database schemas and indexes."""
    db_init(DB_PATH)
    reset_caches()


# Initialize DB on module import
init_db()


def get_ml_pipeline() -> AnomalyDetectionPipeline:
    """
    Retrieve or initialize the Isolation Forest anomaly pipeline.
    Safely loads persisted joblib model or fits on baseline training telemetry.
    """
    global _ml_pipeline
    if _ml_pipeline is not None and _ml_pipeline.is_fitted:
        return _ml_pipeline

    if MODEL_PATH.exists():
        try:
            _ml_pipeline = AnomalyDetectionPipeline.load(MODEL_PATH)
            logger.info("Loaded persisted ML anomaly pipeline from %s", MODEL_PATH)
            return _ml_pipeline
        except Exception as exc:
            logger.warning("Failed loading persisted model (%s), retraining on baseline...", exc)

    # Train on synthetic baseline training telemetry
    training_file = DATA_DIR / "training_telemetry.csv"
    if training_file.exists():
        res = ingestion_engine.process_file(training_file)
        _ml_pipeline = AnomalyDetectionPipeline()
        _ml_pipeline.fit(res.events)
        try:
            _ml_pipeline.save(MODEL_PATH)
            logger.info("Fitted and saved ML anomaly pipeline to %s", MODEL_PATH)
        except Exception as exc:
            logger.warning("Could not persist model artifact: %s", exc)
    else:
        # Fallback empty pipeline
        _ml_pipeline = AnomalyDetectionPipeline()

    return _ml_pipeline


def execute_full_detection_pipeline(
    conn: sqlite3.Connection,
    events: Optional[List[SecurityEvent]] = None,
) -> Dict[str, Any]:
    """
    Execute rule-based detection, ML anomaly scoring, and threat risk correlation.
    Persists findings into the database.
    """
    start_time = time.perf_counter()

    # Sync engine caches with currently persisted alert fingerprints
    existing_alert_fps = {r[0] for r in conn.execute("SELECT fingerprint FROM alerts WHERE fingerprint IS NOT NULL").fetchall()}
    detection_engine.seen_alert_fingerprints = set(existing_alert_fps)
    risk_engine.seen_incident_fingerprints = set(existing_alert_fps)

    # If no events explicitly passed, load recent events from database
    if events is None:
        rows = conn.execute("SELECT * FROM events ORDER BY timestamp ASC, id ASC").fetchall()
        events = [
            SecurityEvent(
                timestamp=r["timestamp"],
                source_ip=r["source_ip"],
                destination_ip=r["destination_ip"],
                username=r["username"],
                event_type=r["event_type"],
                status=r["status"],
                resource=r["resource"],
                payload_size=r["payload_size"],
                fingerprint=r["fingerprint"],
            )
            for r in rows
        ]

    if not events:
        return {
            "total_events_analyzed": 0,
            "rule_alerts_generated": 0,
            "anomalies_detected": 0,
            "incidents_created": 0,
            "duration_ms": 0.0,
        }

    # 1. Rule-Based Threat Detection
    rule_alerts = detection_engine.detect(events)

    # 2. Machine-Learning Anomaly Detection
    anomalies = []
    try:
        pipeline = get_ml_pipeline()
        if pipeline.is_fitted:
            anomalies = pipeline.score(events)
            insert_anomalies(conn, anomalies)
    except Exception as exc:
        logger.warning("ML anomaly scoring encountered an issue: %s", exc)

    # 3. Threat Risk Assessment & Incident Correlation
    incidents = risk_engine.assess_and_correlate(
        events=events,
        rule_alerts=rule_alerts,
        anomaly_findings=anomalies,
    )

    # 4. Persist Rule Alerts
    for alert in rule_alerts:
        cat = RULE_CATEGORY_MAP.get(alert.rule_name, alert.rule_name)
        insert_or_update_alert(
            conn=conn,
            timestamp=alert.timestamp,
            source_ip=alert.entity_value if alert.entity_type == "source_ip" else "N/A",
            category=cat,
            severity=alert.severity,
            risk_score=85 if alert.severity == "High" else 95 if alert.severity == "Critical" else 50,
            description=alert.explanation,
            evidence=[alert.explanation, f"Observed: {alert.observed_value} (Threshold: {alert.threshold})"],
            recommendation=alert.recommended_investigation_step,
            fingerprint=alert.fingerprint,
            alert_id=alert.alert_id,
            entity_type=alert.entity_type,
            entity_value=alert.entity_value,
            confidence=0.85,
            mitre_technique=alert.mitre_technique,
            related_event_ids=alert.related_event_ids,
        )

    # 5. Persist Correlated Incidents
    for inc in incidents:
        insert_or_update_alert(
            conn=conn,
            timestamp=inc.last_seen,
            source_ip=inc.entity_value if inc.entity_type == "source_ip" else "N/A",
            category=inc.title,
            severity=inc.severity,
            risk_score=inc.composite_risk_score,
            description=inc.risk_explanation,
            evidence=[rf.observed_evidence for rf in inc.risk_breakdown] or [inc.risk_explanation],
            recommendation=" ".join(inc.defensive_recommendations),
            fingerprint=inc.fingerprint,
            alert_id=inc.incident_id,
            entity_type=inc.entity_type,
            entity_value=inc.entity_value,
            confidence=inc.confidence,
            anomaly_score=inc.anomaly_score,
            is_confirmed=inc.is_confirmed,
            mitre_technique=", ".join(inc.mitre_techniques) if inc.mitre_techniques else "T1110",
            related_event_ids=inc.related_event_ids,
        )

    duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
    return {
        "total_events_analyzed": len(events),
        "rule_alerts_generated": len(rule_alerts),
        "anomalies_detected": sum(1 for a in anomalies if a.is_anomaly),
        "incidents_created": len(incidents),
        "duration_ms": duration_ms,
    }


# =====================================================================
# Global Exception Handlers (Prevent Stack Trace & Path Leakage)
# =====================================================================

@app.exception_handler(Exception)
async def global_unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Mask unexpected internal exceptions to prevent information leakage."""
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "detail": "An internal error occurred while processing the request.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# =====================================================================
# REST Endpoints
# =====================================================================

@app.get("/", include_in_schema=False)
def serve_home():
    """Serve frontend index if available, otherwise return health information."""
    dist_index = WEB_DIR / "dist" / "index.html"
    if dist_index.exists():
        return FileResponse(dist_index)
    index_file = WEB_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "service": "CyberShield AI REST API",
        "version": "1.0.0",
        "status": "online",
        "docs_url": "/docs",
    }


@app.get("/api/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """System health check and diagnostic status."""
    return HealthResponse(
        status="ok",
        service="CyberShield AI",
        database="sqlite",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/api/logs/upload", response_model=UploadLogsResponse)
async def upload_security_logs(file: UploadFile = File(...)) -> UploadLogsResponse:
    """
    Ingest enterprise security telemetry from a CSV file.
    Validates CSV schema, data types, normalizes timestamps, enforces size limits,
    detects duplicates, and executes detection pipelines.
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Upload a valid .csv file.",
        )

    # Read and enforce file size constraint (10 MB)
    raw_content = await file.read()
    if len(raw_content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
            detail=f"File exceeds maximum allowed limit of {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )

    try:
        csv_text = raw_content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File encoding error. CSV must be UTF-8 encoded.",
        )

    # Retrieve existing fingerprints from DB to avoid cross-upload duplicate ingestion
    with get_db_connection(DB_PATH) as conn:
        existing_fps = {r[0] for r in conn.execute("SELECT fingerprint FROM events WHERE fingerprint IS NOT NULL").fetchall()}

    # Process and validate using SecurityLogIngestion
    processor = SecurityLogIngestion(existing_fingerprints=existing_fps)
    try:
        ingestion_result = processor.process_csv_string(csv_text)
    except (EmptyFileError, InvalidFileError, MissingColumnError, IngestionError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if not ingestion_result.events and ingestion_result.rejected_rows:
        sample_rejected = [
            {"line": r.line_number, "reason": r.reason}
            for r in ingestion_result.rejected_rows[:10]
        ]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "No valid rows found in CSV", "rejected": sample_rejected},
        )

    if ingestion_result.total_rows == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded CSV file is empty or missing headers.",
        )

    # Persist accepted events and run detection
    new_events = 0
    with get_db_connection(DB_PATH) as conn:
        new_events = insert_events(conn, ingestion_result.events)
        detection_summary = execute_full_detection_pipeline(conn, ingestion_result.events)
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    rejected_summaries = [
        RejectedRowSummary(line=r.line_number, reason=r.reason)
        for r in ingestion_result.rejected_rows[:10]
    ]

    return UploadLogsResponse(
        message="CSV processed",
        rows_received=ingestion_result.total_rows,
        valid_rows=ingestion_result.accepted_count,
        new_events=new_events,
        rejected_count=ingestion_result.rejected_count,
        duplicate_count=ingestion_result.duplicate_count,
        rejected_rows=rejected_summaries,
        total_alerts=total_alerts,
        detection_summary=detection_summary,
    )


@app.post("/api/detection/run", response_model=DetectionRunResponse)
def trigger_detection() -> DetectionRunResponse:
    """
    On-demand execution of rule-based detection, ML anomaly scoring,
    and threat risk assessment across all persisted security events.
    """
    with get_db_connection(DB_PATH) as conn:
        summary = execute_full_detection_pipeline(conn)

    return DetectionRunResponse(
        message="Detection completed successfully",
        total_events_analyzed=summary["total_events_analyzed"],
        rule_alerts_generated=summary["rule_alerts_generated"],
        anomalies_detected=summary["anomalies_detected"],
        incidents_created=summary["incidents_created"],
        duration_ms=summary["duration_ms"],
    )


@app.get("/api/events", response_model=EventListResponse)
def list_events(
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    username: Optional[str] = Query(None, description="Filter by username"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (success/failed)"),
    search: Optional[str] = Query(None, description="Global search string"),
) -> EventListResponse:
    """Retrieve paginated security events with multi-field filtering."""
    query = "SELECT * FROM events WHERE 1=1"
    count_query = "SELECT COUNT(*) FROM events WHERE 1=1"
    params: List[Any] = []

    if username:
        query += " AND username = ?"
        count_query += " AND username = ?"
        params.append(username.strip())
    if source_ip:
        query += " AND source_ip = ?"
        count_query += " AND source_ip = ?"
        params.append(source_ip.strip())
    if event_type:
        query += " AND event_type = ?"
        count_query += " AND event_type = ?"
        params.append(event_type.strip().lower())
    if status_filter and status_filter.lower() != "all":
        query += " AND status = ?"
        count_query += " AND status = ?"
        params.append(status_filter.strip().lower())
    if search:
        search_pattern = f"%{search.strip()}%"
        clause = " AND (source_ip LIKE ? OR username LIKE ? OR event_type LIKE ? OR resource LIKE ?)"
        query += clause
        count_query += clause
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    with get_db_connection(DB_PATH) as conn:
        total = conn.execute(count_query, params).fetchone()[0]
        paginated_query = query + " ORDER BY id DESC LIMIT ? OFFSET ?"
        rows = conn.execute(paginated_query, params + [limit, offset]).fetchall()

    event_schemas = [SecurityEventSchema.model_validate(format_event_dict(r)) for r in rows]
    return EventListResponse(
        total=total,
        count=len(event_schemas),
        limit=limit,
        offset=offset,
        events=event_schemas,
    )


@app.get("/api/events/{event_id}", response_model=SecurityEventSchema)
def get_event_detail(event_id: int) -> SecurityEventSchema:
    """Retrieve full details of a specific security event."""
    with get_db_connection(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return SecurityEventSchema.model_validate(format_event_dict(row))


@app.get("/api/alerts", response_model=AlertListResponse)
def list_alerts(
    limit: int = Query(500, ge=1, le=1000, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    severity: Optional[str] = Query(None, description="Filter by severity (Low, Medium, High, Critical)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by triage status (Open, Resolved)"),
    search: Optional[str] = Query(None, description="Search term in IP, category, or ID"),
    entity: Optional[str] = Query(None, description="Filter by entity identity (username or IP)"),
) -> AlertListResponse:
    """Retrieve paginated threat alerts and correlated incidents with filters."""
    query = "SELECT * FROM alerts WHERE 1=1"
    count_query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
    params: List[Any] = []

    if severity and severity.lower() != "all":
        query += " AND LOWER(severity) = ?"
        count_query += " AND LOWER(severity) = ?"
        params.append(severity.strip().lower())
    if status_filter and status_filter.lower() != "all":
        query += " AND LOWER(status) = ?"
        count_query += " AND LOWER(status) = ?"
        params.append(status_filter.strip().lower())
    if entity:
        query += " AND (entity_value = ? OR source_ip = ?)"
        count_query += " AND (entity_value = ? OR source_ip = ?)"
        params.extend([entity.strip(), entity.strip()])
    if search:
        search_pattern = f"%{search.strip()}%"
        clause = " AND (source_ip LIKE ? OR category LIKE ? OR CAST(id AS TEXT) LIKE ? OR entity_value LIKE ?)"
        query += clause
        count_query += clause
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    with get_db_connection(DB_PATH) as conn:
        total = conn.execute(count_query, params).fetchone()[0]
        paginated_query = query + " ORDER BY id DESC LIMIT ? OFFSET ?"
        rows = conn.execute(paginated_query, params + [limit, offset]).fetchall()

    alert_schemas = [AlertResponse.model_validate(format_alert_dict(r)) for r in rows]
    return AlertListResponse(
        total=total,
        count=len(alert_schemas),
        limit=limit,
        offset=offset,
        alerts=alert_schemas,
    )


@app.get("/api/alerts/{alert_id}", response_model=AlertResponse)
def get_alert_detail(alert_id: int) -> AlertResponse:
    """Retrieve granular details for a specific threat alert or incident."""
    with get_db_connection(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return AlertResponse.model_validate(format_alert_dict(row))


@app.patch("/api/alerts/{alert_id}")
def update_alert_status(alert_id: int, payload: AlertStatusUpdate):
    """Update SOC triage status of an alert (Open, Investigating, Resolved, Dismissed)."""
    valid_statuses = {"Open", "Investigating", "Resolved", "Dismissed"}
    normalized_status = payload.status.title()
    if normalized_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Status must be one of: {', '.join(sorted(valid_statuses))}",
        )

    with get_db_connection(DB_PATH) as conn:
        cur = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (normalized_status, alert_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    return {"updated": True, "id": alert_id, "status": normalized_status}


@app.get("/api/dashboard/stats", response_model=DashboardStatsResponse)
def get_dashboard_statistics() -> DashboardStatsResponse:
    """Aggregate executive summary metrics for SOC monitoring overview."""
    with get_db_connection(DB_PATH) as conn:
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE LOWER(status) = 'open'").fetchone()[0]
        high_critical = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE LOWER(severity) IN ('high', 'critical')"
        ).fetchone()[0]

        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
        ).fetchall()
        status_rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM alerts GROUP BY status"
        ).fetchall()

        recent_days = conn.execute("""
            SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS count
            FROM events
            GROUP BY day
            ORDER BY day DESC
            LIMIT 7
        """).fetchall()

        ml_anomalies = conn.execute("SELECT COUNT(*) FROM anomalies WHERE is_anomaly = 1").fetchone()[0]

        top_ips = conn.execute("""
            SELECT source_ip AS entity, COUNT(*) AS count
            FROM alerts
            WHERE source_ip != 'N/A' AND source_ip != ''
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 5
        """).fetchall()

        top_users = conn.execute("""
            SELECT username AS entity, COUNT(*) AS count
            FROM events
            WHERE status IN ('failed', 'denied')
            GROUP BY username
            ORDER BY count DESC
            LIMIT 5
        """).fetchall()

    return DashboardStatsResponse(
        processed_events=total_events,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        high_critical_alerts=high_critical,
        severity_distribution={r["severity"]: r["count"] for r in severity_rows},
        status_distribution={r["status"]: r["count"] for r in status_rows},
        event_trend=[{"date": r["day"], "count": r["count"]} for r in reversed(recent_days)],
        ml_anomaly_count=ml_anomalies,
        top_source_ips=[{"entity": r["entity"], "count": r["count"]} for r in top_ips],
        top_targeted_users=[{"entity": r["entity"], "count": r["count"]} for r in top_users],
    )


# =====================================================================
# Demo / Backward Compatibility Routes
# =====================================================================

@app.post("/api/demo/reset")
def reset_demo():
    """Clear all events, alerts, and anomalies from the database."""
    with get_db_connection(DB_PATH) as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM anomalies")
    reset_caches()
    return {"reset": True, "message": "Demo events, alerts, and anomalies cleared."}


@app.post("/api/demo/sample")
def load_sample():
    """Load sample logs, execute detection pipeline, and return summary counts."""
    sample_file = DATA_DIR / "sample_logs.csv"
    if not sample_file.exists():
        sample_file = ROOT / "backend" / "sample_logs.csv"

    with get_db_connection(DB_PATH) as conn:
        existing_fps = {r[0] for r in conn.execute("SELECT fingerprint FROM events WHERE fingerprint IS NOT NULL").fetchall()}

    processor = SecurityLogIngestion(existing_fingerprints=existing_fps)
    ingestion_result = processor.process_file(sample_file)

    with get_db_connection(DB_PATH) as conn:
        new_events = insert_events(conn, ingestion_result.events)
        execute_full_detection_pipeline(conn, ingestion_result.events)
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    return {
        "message": "Synthetic sample processed",
        "valid_rows": ingestion_result.accepted_count,
        "new_events": new_events,
        "total_alerts": total_alerts,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
