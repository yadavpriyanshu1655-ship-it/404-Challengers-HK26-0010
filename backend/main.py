from __future__ import annotations

import csv
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(__import__("os").environ.get("CYBERSHIELD_DB_PATH", str(ROOT / "cybershield.db")))
WEB_DIR = ROOT / "frontend"

app = FastAPI(title="CyberShield AI", version="1.0.0",
              description="Explainable synthetic security-log detection MVP")
app.mount("/assets", StaticFiles(directory=str(WEB_DIR / "assets")), name="assets")


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, source_ip TEXT NOT NULL,
            username TEXT NOT NULL, event_type TEXT NOT NULL,
            status TEXT NOT NULL, fingerprint TEXT UNIQUE
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, source_ip TEXT NOT NULL,
            category TEXT NOT NULL, severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL, description TEXT NOT NULL,
            evidence TEXT NOT NULL, recommendation TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open', fingerprint TEXT UNIQUE
        )""")


init_db()


def parse_dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize(row: dict) -> dict:
    lowered = {str(k).strip().lower(): (v or "").strip() for k, v in row.items() if k}
    aliases = {
        "timestamp": ["timestamp", "time", "datetime", "event_time"],
        "source_ip": ["source_ip", "src_ip", "ip", "ip_address"],
        "username": ["username", "user", "account"],
        "event_type": ["event_type", "event", "action", "type"],
        "status": ["status", "result", "outcome"],
    }
    result = {}
    for target, options in aliases.items():
        result[target] = next((lowered[o] for o in options if lowered.get(o)), "")
    missing = [k for k, v in result.items() if not v]
    if missing:
        raise ValueError("Missing required values: " + ", ".join(missing))
    result["timestamp"] = parse_dt(result["timestamp"]).isoformat()
    result["event_type"] = result["event_type"].lower()
    result["status"] = result["status"].lower()
    return result


def add_alert(conn, event_time, ip, category, severity, score, description, evidence, recommendation, fingerprint):
    conn.execute("""INSERT OR IGNORE INTO alerts
        (timestamp, source_ip, category, severity, risk_score, description, evidence, recommendation, status, fingerprint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?)""",
        (event_time, ip, category, severity, score, description, evidence, recommendation, fingerprint))


def detect_for_ip(conn, ip: str):
    rows = conn.execute(
        "SELECT * FROM events WHERE source_ip=? ORDER BY timestamp ASC, id ASC", (ip,)
    ).fetchall()
    events = []
    for row in rows:
        try:
            dt = parse_dt(row["timestamp"])
        except Exception:
            continue
        status = row["status"].lower()
        is_failed = status in {"failed", "failure", "denied", "error"} or status.startswith("fail")
        is_success = status in {"success", "successful", "ok", "accepted"}
        if "login" in row["event_type"] or "auth" in row["event_type"] or row["event_type"] in {"signin", "sign_in"}:
            events.append((row, dt, is_failed, is_success))

    # Every rolling 10-minute window with at least five failures is a brute-force pattern.
    for i, (row, dt, failed, _) in enumerate(events):
        if not failed:
            continue
        window = [(r, t) for r, t, f, _ in events if f and dt - timedelta(minutes=10) <= t <= dt]
        if len(window) >= 5:
            first = window[0][1].isoformat()
            last = window[-1][1].isoformat()
            fp = f"bruteforce|{ip}|{first}|{last}|{len(window)}"
            add_alert(conn, last, ip, "Brute-force login attempts", "High", 85,
                      f"{len(window)} failed login attempts from {ip} occurred within 10 minutes.",
                      f"Failed attempts: {len(window)}; window: {first} to {last}.",
                      "Review authentication logs, verify the account owner, and apply your organization's rate-limiting or access policy.", fp)
            break

    # Successful login after >=3 failures in the preceding 10 minutes.
    for row, dt, failed, success in events:
        if not success:
            continue
        preceding = [(r, t) for r, t, f, _ in events if f and timedelta(0) <= dt - t <= timedelta(minutes=10)]
        if len(preceding) >= 3:
            fail_times = ", ".join(t.isoformat() for _, t in preceding[-5:])
            fp = f"success-after-failures|{ip}|{dt.isoformat()}|{len(preceding)}"
            add_alert(conn, dt.isoformat(), ip, "Success after repeated failures", "Critical", 95,
                      f"A successful login from {ip} followed {len(preceding)} failed login attempts within 10 minutes.",
                      f"Successful event: {dt.isoformat()}; preceding failed events: {len(preceding)}; failure timestamps: {fail_times}.",
                      "Verify the login with the account owner and investigate related authentication events. Follow your incident-response policy.", fp)


def row_alert(row):
    item = dict(row)
    item["evidence"] = item["evidence"].split("\n")
    return item


@app.get("/")
def home():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CyberShield AI", "database": "sqlite"}


@app.get("/api/dashboard/stats")
def dashboard_stats():
    with connect() as conn:
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='Open'").fetchone()[0]
        high_critical = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('High','Critical')").fetchone()[0]
        severity_rows = conn.execute("SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity").fetchall()
        recent = conn.execute("SELECT substr(timestamp,1,10) AS day, COUNT(*) AS count FROM events GROUP BY day ORDER BY day DESC LIMIT 7").fetchall()
    return {
        "processed_events": total_events,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "high_critical_alerts": high_critical,
        "severity_distribution": {r["severity"]: r["count"] for r in severity_rows},
        "event_trend": [{"date": r["day"], "count": r["count"]} for r in reversed(recent)],
    }


@app.get("/api/alerts")
def list_alerts(severity: Optional[str] = None, status: Optional[str] = None, search: Optional[str] = None):
    query = "SELECT * FROM alerts WHERE 1=1"
    args = []
    if severity and severity.lower() != "all":
        query += " AND severity=?"
        args.append(severity.title())
    if status and status.lower() != "all":
        query += " AND status=?"
        args.append(status.title())
    if search:
        query += " AND (source_ip LIKE ? OR category LIKE ? OR CAST(id AS TEXT) LIKE ?)"
        pattern = f"%{search}%"
        args.extend([pattern, pattern, pattern])
    query += " ORDER BY id DESC LIMIT 500"
    with connect() as conn:
        rows = conn.execute(query, args).fetchall()
    return {"count": len(rows), "alerts": [row_alert(r) for r in rows]}


@app.get("/api/alerts/{alert_id}")
def alert_detail(alert_id: int):
    with connect() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row_alert(row)


class StatusUpdate(BaseModel):
    status: str


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, payload: StatusUpdate):
    if payload.status not in {"Open", "Resolved"}:
        raise HTTPException(status_code=400, detail="Status must be Open or Resolved")
    with connect() as conn:
        cur = conn.execute("UPDATE alerts SET status=? WHERE id=?", (payload.status, alert_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
    return {"updated": True, "id": alert_id, "status": payload.status}


@app.post("/api/logs/upload")
async def upload_logs(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Upload a .csv file.")
    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV exceeds the 5 MB demo limit.")
    try:
        text = raw.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("CSV has no header row.")
        accepted, rejected = [], []
        for line_no, raw_row in enumerate(reader, start=2):
            try:
                item = normalize(raw_row)
                item["fingerprint"] = "|".join(item[k] for k in ("timestamp", "source_ip", "username", "event_type", "status"))
                accepted.append((line_no, item))
            except Exception as exc:
                rejected.append({"line": line_no, "reason": str(exc)})
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded.")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {exc}")
    if not accepted and rejected:
        raise HTTPException(status_code=400, detail={"message": "No valid rows found", "rejected": rejected[:10]})
    inserted = 0
    with connect() as conn:
        for _, item in accepted:
            cur = conn.execute("""INSERT OR IGNORE INTO events
                (timestamp, source_ip, username, event_type, status, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (item["timestamp"], item["source_ip"], item["username"], item["event_type"], item["status"], item["fingerprint"]))
            inserted += cur.rowcount
        ips = [r[0] for r in conn.execute("SELECT DISTINCT source_ip FROM events").fetchall()]
        for ip in ips:
            detect_for_ip(conn, ip)
        alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {
        "message": "CSV processed",
        "rows_received": len(accepted) + len(rejected),
        "valid_rows": len(accepted),
        "new_events": inserted,
        "rejected_rows": rejected[:10],
        "total_alerts": alert_count,
    }


@app.post("/api/demo/reset")
def reset_demo():
    with connect() as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM events")
    return {"reset": True, "message": "Demo events and alerts cleared."}


@app.post("/api/demo/sample")
def load_sample():
    sample = ROOT / "backend" / "sample_logs.csv"
    with sample.open("rb") as f:
        content = f.read()
    # Reuse the same ingestion logic by parsing here, avoiding an internal HTTP request.
    text = content.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    accepted = [normalize(row) for row in reader]
    inserted = 0
    with connect() as conn:
        for item in accepted:
            item["fingerprint"] = "|".join(item[k] for k in ("timestamp", "source_ip", "username", "event_type", "status"))
            cur = conn.execute("""INSERT OR IGNORE INTO events
                (timestamp, source_ip, username, event_type, status, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (item["timestamp"], item["source_ip"], item["username"], item["event_type"], item["status"], item["fingerprint"]))
            inserted += cur.rowcount
        for r in conn.execute("SELECT DISTINCT source_ip FROM events").fetchall():
            detect_for_ip(conn, r[0])
        alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {"message": "Synthetic sample processed", "valid_rows": len(accepted), "new_events": inserted, "total_alerts": alerts}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
