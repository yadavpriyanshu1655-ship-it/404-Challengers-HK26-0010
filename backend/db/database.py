"""
CyberShield AI — SQLite Persistence Layer

Manages connection pooling, table schemas, indexes, migrations,
and parameterized queries for security telemetry, threat alerts,
and ML anomaly findings.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple, Union

from backend.models.event import SecurityEvent
from backend.models.alert import ThreatAlert
from backend.models.risk import CorrelatedIncident
from backend.models.anomaly import AnomalyFinding


ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_DB_PATH = ROOT_DIR / "cybershield.db"


def get_db_path() -> Path:
    """Return database file path from environment or default."""
    env_path = os.environ.get("CYBERSHIELD_DB_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB_PATH


def create_connection(db_path: Optional[Union[str, Path]] = None) -> sqlite3.Connection:
    """
    Establish a connection with performance pragmas and row factory enabled.
    """
    target = Path(db_path) if db_path else get_db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db_connection(db_path: Optional[Union[str, Path]] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite connections with automatic commit/rollback."""
    conn = create_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[Union[str, Path]] = None) -> None:
    """
    Create tables, indexes, and apply backward-compatible schema migrations.
    """
    with get_db_connection(db_path) as conn:
        # 1. Security events table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL DEFAULT '10.0.0.1',
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                resource TEXT NOT NULL DEFAULT '/',
                payload_size INTEGER NOT NULL DEFAULT 0,
                fingerprint TEXT UNIQUE
            )
        """)

        # 2. Threat alerts & correlated incidents table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                entity_type TEXT NOT NULL DEFAULT 'source_ip',
                entity_value TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.8,
                anomaly_score REAL,
                is_confirmed INTEGER NOT NULL DEFAULT 0,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                mitre_technique TEXT NOT NULL DEFAULT 'T1110',
                status TEXT NOT NULL DEFAULT 'Open',
                fingerprint TEXT UNIQUE,
                related_event_ids TEXT DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT ''
            )
        """)

        # 3. Machine-learning anomaly findings table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT UNIQUE,
                event_fingerprint TEXT,
                timestamp TEXT,
                entity TEXT,
                is_anomaly INTEGER,
                anomaly_score REAL,
                raw_score REAL,
                contributing_factors TEXT,
                disclaimer TEXT,
                created_at TEXT NOT NULL DEFAULT ''
            )
        """)

        # Migration safety: ensure any existing tables created in earlier phases have all columns
        _ensure_column(conn, "events", "destination_ip", "TEXT NOT NULL DEFAULT '10.0.0.1'")
        _ensure_column(conn, "events", "resource", "TEXT NOT NULL DEFAULT '/'")
        _ensure_column(conn, "events", "payload_size", "INTEGER NOT NULL DEFAULT 0")

        _ensure_column(conn, "alerts", "alert_id", "TEXT")
        _ensure_column(conn, "alerts", "entity_type", "TEXT NOT NULL DEFAULT 'source_ip'")
        _ensure_column(conn, "alerts", "entity_value", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "alerts", "confidence", "REAL NOT NULL DEFAULT 0.8")
        _ensure_column(conn, "alerts", "anomaly_score", "REAL")
        _ensure_column(conn, "alerts", "is_confirmed", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "alerts", "mitre_technique", "TEXT NOT NULL DEFAULT 'T1110'")
        _ensure_column(conn, "alerts", "related_event_ids", "TEXT DEFAULT '[]'")
        _ensure_column(conn, "alerts", "created_at", "TEXT NOT NULL DEFAULT ''")

        # Indexes for rapid filtering and dashboard aggregations
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_username ON events(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_entity_value ON alerts(entity_value)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_event_fp ON anomalies(event_fingerprint)")


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, col_def: str) -> None:
    """Safely add a column to an SQLite table if it does not already exist."""
    cursor = conn.execute(f"PRAGMA table_info({table})")
    existing = [row["name"] for row in cursor.fetchall()]
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")


# =====================================================================
# Database Access Helpers
# =====================================================================

def insert_events(conn: sqlite3.Connection, events: Iterable[Union[SecurityEvent, Dict[str, Any]]]) -> int:
    """
    Insert security events into SQLite using batch execution.
    Skips duplicates based on unique fingerprint.
    Returns the number of newly inserted rows.
    """
    inserted = 0
    sql = """
        INSERT OR IGNORE INTO events
        (timestamp, source_ip, destination_ip, username, event_type, status, resource, payload_size, fingerprint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = []
    for ev in events:
        if isinstance(ev, SecurityEvent):
            d = ev.to_dict()
        else:
            d = dict(ev)
        
        fp = d.get("fingerprint") or "|".join([
            str(d.get("timestamp", "")),
            str(d.get("source_ip", "")),
            str(d.get("username", "")),
            str(d.get("event_type", "")),
            str(d.get("status", "")),
        ])
        params.append((
            str(d.get("timestamp", "")),
            str(d.get("source_ip", "")),
            str(d.get("destination_ip", "10.0.0.1")),
            str(d.get("username", "")),
            str(d.get("event_type", "")).lower(),
            str(d.get("status", "")).lower(),
            str(d.get("resource", "/")),
            int(d.get("payload_size", 0)),
            fp,
        ))

    for p in params:
        cur = conn.execute(sql, p)
        inserted += cur.rowcount

    return inserted


def insert_or_update_alert(
    conn: sqlite3.Connection,
    timestamp: str,
    source_ip: str,
    category: str,
    severity: str,
    risk_score: int,
    description: str,
    evidence: Union[str, List[str]],
    recommendation: Union[str, List[str]],
    fingerprint: str,
    alert_id: Optional[str] = None,
    entity_type: str = "source_ip",
    entity_value: Optional[str] = None,
    confidence: float = 0.8,
    anomaly_score: Optional[float] = None,
    is_confirmed: bool = False,
    mitre_technique: str = "T1110",
    related_event_ids: Optional[List[str]] = None,
    status: str = "Open",
) -> int:
    """
    Insert a threat alert or update an existing one if the fingerprint matches.
    """
    now_utc = datetime.now(timezone.utc).isoformat()
    if isinstance(evidence, list):
        evidence_str = "\n".join(evidence)
    else:
        evidence_str = str(evidence)

    if isinstance(recommendation, list):
        recommendation_str = " ".join(recommendation)
    else:
        recommendation_str = str(recommendation)

    related_json = json.dumps(related_event_ids or [])
    val = entity_value if entity_value is not None else source_ip

    cur = conn.execute("""
        INSERT INTO alerts
        (alert_id, timestamp, source_ip, entity_type, entity_value, category, severity,
         risk_score, confidence, anomaly_score, is_confirmed, description, evidence,
         recommendation, mitre_technique, status, fingerprint, related_event_ids, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
            severity=excluded.severity,
            risk_score=MAX(alerts.risk_score, excluded.risk_score),
            confidence=MAX(alerts.confidence, excluded.confidence),
            anomaly_score=COALESCE(excluded.anomaly_score, alerts.anomaly_score),
            is_confirmed=MAX(alerts.is_confirmed, excluded.is_confirmed),
            description=excluded.description,
            evidence=excluded.evidence,
            recommendation=excluded.recommendation
    """, (
        alert_id, timestamp, source_ip, entity_type, val, category, severity,
        int(risk_score), float(confidence), anomaly_score, 1 if is_confirmed else 0,
        description, evidence_str, recommendation_str, mitre_technique, status,
        fingerprint, related_json, now_utc
    ))
    return cur.rowcount


def insert_anomalies(conn: sqlite3.Connection, findings: Iterable[AnomalyFinding]) -> int:
    """Persist machine-learning anomaly findings."""
    inserted = 0
    now_utc = datetime.now(timezone.utc).isoformat()
    sql = """
        INSERT OR IGNORE INTO anomalies
        (finding_id, event_fingerprint, timestamp, entity, is_anomaly, anomaly_score, raw_score, contributing_factors, disclaimer, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    for f in findings:
        cur = conn.execute(sql, (
            f.finding_id,
            f.event_fingerprint,
            f.timestamp,
            f.entity,
            1 if f.is_anomaly else 0,
            f.anomaly_score,
            f.raw_score,
            json.dumps(f.contributing_factors),
            f.disclaimer,
            now_utc,
        ))
        inserted += cur.rowcount
    return inserted


def format_alert_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a database alert row into a normalized dictionary."""
    d = dict(row)
    evidence_val = d.get("evidence", "")
    if isinstance(evidence_val, str):
        # Format as list of strings for both legacy and enriched endpoints
        lines = [line.strip() for line in evidence_val.split("\n") if line.strip()]
        d["evidence"] = lines if lines else [evidence_val]
    else:
        d["evidence"] = list(evidence_val)

    related = d.get("related_event_ids")
    if isinstance(related, str):
        try:
            d["related_event_ids"] = json.loads(related)
        except Exception:
            d["related_event_ids"] = [r.strip() for r in related.split(",") if r.strip()]
    else:
        d["related_event_ids"] = related or []

    d["is_confirmed"] = bool(d.get("is_confirmed", 0))
    d["confidence"] = float(d.get("confidence", 0.8))
    if d.get("anomaly_score") is not None:
        d["anomaly_score"] = float(d["anomaly_score"])

    # Ensure backward compatible fields have non-empty values
    if not d.get("alert_id"):
        d["alert_id"] = f"CS-ALERT-{d['id']:04d}"
    if not d.get("entity_value"):
        d["entity_value"] = d.get("source_ip", "")

    return d


def format_event_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a database event row into a normalized dictionary."""
    d = dict(row)
    return d
