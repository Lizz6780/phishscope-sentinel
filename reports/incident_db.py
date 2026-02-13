import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "incidents.db"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT UNIQUE NOT NULL,
                source_email TEXT,
                verdict TEXT,
                severity TEXT,
                risk_score REAL,
                timestamp TEXT,
                urls_json TEXT NOT NULL,
                attachments_json TEXT NOT NULL,
                mitre_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                owner TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


def insert_incident(report, file_name):
    init_db()
    now = datetime.now(UTC).isoformat()

    urls_json = json.dumps(report.get("urls", []))
    attachments_json = json.dumps(report.get("attachments", []))
    mitre_json = json.dumps(report.get("mitre", []))

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO incidents (
                file_name, source_email, verdict, severity, risk_score, timestamp,
                urls_json, attachments_json, mitre_json, status, owner, notes,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_name,
                report.get("source_email", ""),
                report.get("verdict", "UNKNOWN"),
                report.get("severity", "LOW"),
                float(report.get("risk_score", 0)),
                report.get("timestamp", now),
                urls_json,
                attachments_json,
                mitre_json,
                report.get("status", "New"),
                report.get("owner", ""),
                report.get("notes", ""),
                now,
                now,
            ),
        )


def list_incidents():
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                file_name,
                source_email,
                verdict,
                severity,
                risk_score,
                timestamp,
                urls_json,
                attachments_json,
                mitre_json,
                status,
                owner,
                notes,
                created_at,
                updated_at
            FROM incidents
            ORDER BY timestamp DESC
            """
        ).fetchall()

    incidents = []
    for row in rows:
        incidents.append(
            {
                "id": row["id"],
                "file": row["file_name"],
                "source_email": row["source_email"],
                "verdict": row["verdict"],
                "severity": row["severity"],
                "risk_score": row["risk_score"],
                "timestamp": row["timestamp"],
                "urls": json.loads(row["urls_json"] or "[]"),
                "attachments": json.loads(row["attachments_json"] or "[]"),
                "mitre": json.loads(row["mitre_json"] or "[]"),
                "status": row["status"],
                "owner": row["owner"],
                "notes": row["notes"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
    return incidents


def update_incident_workflow(incident_id, status, owner, notes):
    init_db()
    now = datetime.now(UTC).isoformat()

    with _connect() as conn:
        conn.execute(
            """
            UPDATE incidents
            SET status = ?, owner = ?, notes = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, owner, notes, now, incident_id),
        )


def bootstrap_from_json_reports(reports_dir):
    init_db()
    reports_path = Path(reports_dir)
    if not reports_path.exists():
        return

    with _connect() as conn:
        row = conn.execute("SELECT COUNT(1) AS n FROM incidents").fetchone()
        if row["n"] > 0:
            return

    files = sorted(reports_path.glob("incident_*.json"))
    for file_path in files:
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue

        now = datetime.now(UTC).isoformat()
        urls_json = json.dumps(report.get("urls", []))
        attachments_json = json.dumps(report.get("attachments", []))
        mitre_json = json.dumps(report.get("mitre", []))

        with _connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO incidents (
                    file_name, source_email, verdict, severity, risk_score, timestamp,
                    urls_json, attachments_json, mitre_json, status, owner, notes,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_path.name,
                    report.get("source_email", ""),
                    report.get("verdict", "UNKNOWN"),
                    report.get("severity", "LOW"),
                    float(report.get("risk_score", 0)),
                    report.get("timestamp", now),
                    urls_json,
                    attachments_json,
                    mitre_json,
                    report.get("status", "New"),
                    report.get("owner", ""),
                    report.get("notes", ""),
                    now,
                    now,
                ),
            )
