"""
database.py — WebSec Scanner · Pure sqlite3 database layer
Tables: api_keys, admin_users, scans
"""

import sqlite3
import secrets
import hashlib
import json
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List, Dict, Any

DB_PATH = "websec.db"

# ── Connection helper ──────────────────────────────────────────────────────────

@contextmanager
def get_conn():
    """Yield a WAL-mode connection; commit on success, rollback on error."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row          # dict-like access
    conn.execute("PRAGMA journal_mode=WAL") # safe for concurrent FastAPI workers
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ─────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT    NOT NULL UNIQUE,
    label       TEXT    NOT NULL DEFAULT '',   -- human-readable note, no PII required
    active      INTEGER NOT NULL DEFAULT 1,    -- 1 = active, 0 = revoked
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,            -- bcrypt hash (see auth helpers below)
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip       TEXT    NOT NULL,
    api_key_id      INTEGER NOT NULL REFERENCES api_keys(id),
    target_url      TEXT    NOT NULL,
    scan_type       TEXT    NOT NULL CHECK(scan_type IN ('quickscan', 'deepscan')),
    status          TEXT    NOT NULL DEFAULT 'pending'
                                CHECK(status IN ('pending','running','done','error')),
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    endpoints_count INTEGER NOT NULL DEFAULT 0,
    sqli_count      INTEGER NOT NULL DEFAULT 0,
    xss_count       INTEGER NOT NULL DEFAULT 0,
    info_count      INTEGER NOT NULL DEFAULT 0,
    total_vulns     INTEGER NOT NULL DEFAULT 0,
    vulns_json      TEXT    NOT NULL DEFAULT '[]'   -- JSON array of vuln dicts
);
"""


def init_db() -> None:
    """Create tables and seed a default admin user if the DB is empty."""
    with get_conn() as conn:
        conn.executescript(SCHEMA)

        # Seed default admin (only if table is empty)
        row = conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()
        if row[0] == 0:
            from passlib.hash import bcrypt as _bcrypt   # imported here so the
            default_hash = _bcrypt.hash("changeme123!")  # module stays importable
            conn.execute(                                # without passlib at schema time
                "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?,?,?)",
                ("admin", default_hash, _now()),
            )

        # Seed a bootstrap API key (only if table is empty)
        row = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()
        if row[0] == 0:
            key = _generate_key()
            conn.execute(
                "INSERT INTO api_keys (key, label, active, created_at) VALUES (?,?,1,?)",
                (key, "bootstrap", _now()),
            )
            print(f"[database] Bootstrap API key: {key}")


# ── Internal helpers ───────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _generate_key(prefix: str = "wsk") -> str:
    """Return a cryptographically random prefixed API key."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


# ── api_keys helpers ───────────────────────────────────────────────────────────

def create_api_key(label: str = "") -> Dict[str, Any]:
    key = _generate_key()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO api_keys (key, label, active, created_at) VALUES (?,?,1,?) RETURNING id",
            (key, label, _now()),
        )
        row = cur.fetchone()
    return {"id": row["id"], "key": key, "label": label, "active": True}


def get_api_key(key: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM api_keys WHERE key=? AND active=1", (key,)
        ).fetchone()


def revoke_api_key(key_id: int) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE api_keys SET active=0 WHERE id=?", (key_id,)
        )
    return cur.rowcount > 0


def list_api_keys() -> List[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, label, active, created_at FROM api_keys ORDER BY id DESC"
        ).fetchall()


# ── admin_users helpers ────────────────────────────────────────────────────────

def get_admin_by_username(username: str) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM admin_users WHERE username=?", (username,)
        ).fetchone()


def create_admin(username: str, password: str) -> int:
    from passlib.hash import bcrypt as _bcrypt
    pw_hash = _bcrypt.hash(password)
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?,?,?) RETURNING id",
            (username, pw_hash, _now()),
        )
        return cur.fetchone()["id"]


def verify_admin_password(username: str, password: str) -> bool:
    from passlib.hash import bcrypt as _bcrypt
    row = get_admin_by_username(username)
    if not row:
        return False
    return _bcrypt.verify(password, row["password_hash"])


# ── scans helpers ──────────────────────────────────────────────────────────────

def create_scan(
    client_ip: str,
    api_key_id: int,
    target_url: str,
    scan_type: str,
) -> int:
    """Insert a new scan row in 'pending' status; return its id."""
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans
               (client_ip, api_key_id, target_url, scan_type, status, started_at)
               VALUES (?,?,?,?,?,?) RETURNING id""",
            (client_ip, api_key_id, target_url, scan_type, "pending", _now()),
        )
        return cur.fetchone()["id"]


def update_scan_running(scan_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET status='running' WHERE id=?", (scan_id,)
        )


def finish_scan(
    scan_id: int,
    *,
    vulns: List[Dict],
    endpoints_count: int,
    sqli_count: int,
    xss_count: int,
    info_count: int,
    error: bool = False,
) -> None:
    status = "error" if error else "done"
    with get_conn() as conn:
        conn.execute(
            """UPDATE scans SET
               status=?, finished_at=?,
               endpoints_count=?, sqli_count=?, xss_count=?, info_count=?,
               total_vulns=?, vulns_json=?
               WHERE id=?""",
            (
                status, _now(),
                endpoints_count, sqli_count, xss_count, info_count,
                len(vulns), json.dumps(vulns),
                scan_id,
            ),
        )


def get_scan(scan_id: int) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()


def get_scans_for_key(api_key_id: int, limit: int = 50) -> List[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """SELECT id, target_url, scan_type, status, started_at, finished_at,
                      endpoints_count, sqli_count, xss_count, info_count, total_vulns
               FROM scans WHERE api_key_id=? ORDER BY id DESC LIMIT ?""",
            (api_key_id, limit),
        ).fetchall()


# ── Admin dashboard aggregates (no PII beyond client_ip) ──────────────────────

def get_aggregate_stats() -> Dict[str, Any]:
    """Summary counts for the admin dashboard."""
    with get_conn() as conn:
        totals = conn.execute(
            """SELECT
                COUNT(*)                        AS total_scans,
                SUM(sqli_count)                 AS total_sqli,
                SUM(xss_count)                  AS total_xss,
                SUM(info_count)                 AS total_info,
                SUM(total_vulns)                AS total_vulns,
                SUM(CASE WHEN scan_type='quickscan' THEN 1 ELSE 0 END) AS quick_count,
                SUM(CASE WHEN scan_type='deepscan'  THEN 1 ELSE 0 END) AS deep_count,
                SUM(CASE WHEN status='error'        THEN 1 ELSE 0 END) AS error_count
               FROM scans"""
        ).fetchone()

        recent_ips = conn.execute(
            """SELECT DISTINCT client_ip, MAX(started_at) AS last_seen
               FROM scans GROUP BY client_ip ORDER BY last_seen DESC LIMIT 100"""
        ).fetchall()

    return {
        "totals": dict(totals),
        "recent_client_ips": [dict(r) for r in recent_ips],
    }


# ── CLI bootstrap ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[database] Initialising websec.db …")
    init_db()
    print("[database] Done.")
    stats = get_aggregate_stats()
    print(f"[database] Aggregate stats: {stats['totals']}")
