"""
SQLite Database Layer for NetraShield SOC 2.4.0
Handles TelemetrySource, AlertIncident, TriageReport, RuleRepository, DetectionPolicy.
"""
import sqlite3
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

DEFAULT_DB_PATH = "data/netrashield.db"

class DatabaseManager:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    file_path TEXT,
                    event_count INTEGER DEFAULT 0,
                    ingested_at TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rule_repository (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT DEFAULT 'production',
                    severity TEXT NOT NULL,
                    mitre_technique TEXT,
                    content TEXT,
                    enabled INTEGER DEFAULT 1,
                    updated_at TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    min_risk_threshold REAL NOT NULL,
                    contamination REAL NOT NULL,
                    worker_threads INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alert_incidents (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    host TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    mitre_id TEXT,
                    mitre_name TEXT,
                    detection_title TEXT NOT NULL,
                    process_command TEXT,
                    process_image TEXT,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    shannon_entropy REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'Open',
                    raw_ecs TEXT,
                    rule_ids TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS triage_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_events INTEGER NOT NULL,
                    alert_count INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    avg_risk_score REAL NOT NULL,
                    latency_ms REAL NOT NULL
                )
            """)
            conn.commit()

    def save_incidents(self, incidents: List[Dict[str, Any]]) -> None:
        if not incidents:
            return
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            for inc in incidents:
                raw_ecs_str = json.dumps(inc.get("raw_ecs", {})) if isinstance(inc.get("raw_ecs"), dict) else str(inc.get("raw_ecs", ""))
                rule_ids_str = json.dumps(inc.get("rule_ids", [])) if isinstance(inc.get("rule_ids"), list) else str(inc.get("rule_ids", ""))
                cursor.execute("""
                    INSERT OR REPLACE INTO alert_incidents (
                        alert_id, timestamp, host, severity, risk_score,
                        mitre_id, mitre_name, detection_title, process_command,
                        process_image, dest_ip, dest_port, shannon_entropy,
                        status, raw_ecs, rule_ids, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    inc.get("alert_id"),
                    inc.get("timestamp", now),
                    inc.get("host", "unknown"),
                    inc.get("severity", "LOW"),
                    float(inc.get("risk_score", 0.0)),
                    inc.get("mitre_id", ""),
                    inc.get("mitre_name", ""),
                    inc.get("detection_title", "Unknown Anomaly"),
                    inc.get("process_command", ""),
                    inc.get("process_image", ""),
                    inc.get("dest_ip", ""),
                    int(inc.get("dest_port", 0) or 0),
                    float(inc.get("shannon_entropy", 0.0)),
                    inc.get("status", "Open"),
                    raw_ecs_str,
                    rule_ids_str,
                    now
                ))
            conn.commit()

    def update_incident_status(self, alert_id: str, new_status: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE alert_incidents SET status = ? WHERE alert_id = ?
            """, (new_status, alert_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_incidents(self, limit: int = 500) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM alert_incidents ORDER BY risk_score DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                try:
                    item["raw_ecs"] = json.loads(item["raw_ecs"]) if item["raw_ecs"] else {}
                except Exception:
                    pass
                try:
                    item["rule_ids"] = json.loads(item["rule_ids"]) if item["rule_ids"] else []
                except Exception:
                    pass
                results.append(item)
            return results

    def save_triage_report(self, report: Dict[str, Any]) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO triage_reports (
                    timestamp, total_events, alert_count, critical_count,
                    high_count, medium_count, low_count, avg_risk_score, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.get("timestamp", datetime.utcnow().isoformat()),
                report.get("total_events", 0),
                report.get("alert_count", 0),
                report.get("critical_count", 0),
                report.get("high_count", 0),
                report.get("medium_count", 0),
                report.get("low_count", 0),
                report.get("avg_risk_score", 0.0),
                report.get("latency_ms", 0.0),
            ))
            conn.commit()
            return cursor.lastrowid

    def get_latest_reports(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM triage_reports ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
