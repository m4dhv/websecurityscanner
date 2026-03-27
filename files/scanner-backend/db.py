"""
Lightweight SQLite persistence layer.
Stores scan results and serves admin dashboard stats.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from models import ScanResult

DB_PATH = os.environ.get("DB_PATH", "siteshield.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT NOT NULL,
                scanned_at  TEXT NOT NULL,
                score       INTEGER,
                ssl_valid   INTEGER,
                ssl_grade   TEXT,
                header_score INTEGER,
                vuln_count  INTEGER,
                perf_score  INTEGER,
                full_json   TEXT
            )
        """)
        conn.commit()


def save_scan(result: ScanResult):
    init_db()
    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO scans
              (url, scanned_at, score, ssl_valid, ssl_grade, header_score, vuln_count, perf_score, full_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.url,
            result.scanned_at.isoformat(),
            result.score,
            int(result.ssl.valid),
            result.ssl.grade,
            result.headers.score,
            result.vulnerabilities.count,
            result.performance.score,
            result.model_dump_json(),
        ))
        conn.commit()


def get_recent_scans(limit: int = 20):
    init_db()
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT url, scanned_at, score, ssl_valid, ssl_grade, vuln_count FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats():
    init_db()
    with _get_conn() as conn:
        row = conn.execute("""
            SELECT
                COUNT(*)          AS total_scans,
                AVG(score)        AS avg_score,
                SUM(CASE WHEN score >= 70 THEN 1 ELSE 0 END) AS safe_count,
                SUM(CASE WHEN score < 40  THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN ssl_valid = 1 THEN 1 ELSE 0 END) AS ssl_valid_count
            FROM scans
        """).fetchone()
    return {
        "total_scans": row["total_scans"] or 0,
        "avg_score": round(row["avg_score"] or 0, 1),
        "safe_count": row["safe_count"] or 0,
        "critical_count": row["critical_count"] or 0,
        "ssl_valid_count": row["ssl_valid_count"] or 0,
    }
