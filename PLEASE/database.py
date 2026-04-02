import sqlite3
import bcrypt
import secrets
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from contextlib import contextmanager

DATABASE_NAME = "websec.db"

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    """Initialize database with required tables"""
    with get_db() as conn:
        c = conn.cursor()
        
        # API Keys table
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Admin Users table
        c.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scans table
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT NOT NULL,
                target_url TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                vulns_json TEXT,
                endpoints_count INTEGER DEFAULT 0,
                sqli_count INTEGER DEFAULT 0,
                xss_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                total_vulns INTEGER DEFAULT 0
            )
        """)
        
        conn.commit()

# API Key Functions
def create_api_key() -> str:
    """Generate a new API key"""
    key = secrets.token_urlsafe(32)
    with get_db() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO api_keys (key, active) VALUES (?, 1)", (key,))
        conn.commit()
    return key

def verify_api_key(key: str) -> bool:
    """Verify if an API key is valid and active"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT active FROM api_keys WHERE key = ?", (key,))
        result = c.fetchone()
        return result is not None and result[0] == 1

def deactivate_api_key(key: str) -> bool:
    """Deactivate an API key"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("UPDATE api_keys SET active = 0 WHERE key = ?", (key,))
        conn.commit()
        return c.rowcount > 0

def list_api_keys() -> List[Dict]:
    """List all API keys"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, key, active, created_at FROM api_keys ORDER BY created_at DESC")
        return [dict(row) for row in c.fetchall()]

# Admin User Functions
def create_admin_user(username: str, password: str) -> bool:
    """Create a new admin user with bcrypt hashed password"""
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
                     (username, password_hash))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_admin_user(username: str, password: str) -> bool:
    """Verify admin credentials"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT password_hash FROM admin_users WHERE username = ?", (username,))
        result = c.fetchone()
        if result:
            return bcrypt.checkpw(password.encode('utf-8'), result[0])
    return False

def admin_exists() -> bool:
    """Check if any admin users exist"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM admin_users")
        return c.fetchone()[0] > 0

# Scan Functions
def save_scan(client_ip: str, target_url: str, scan_type: str, 
              vulnerabilities: List[Dict], endpoints_count: int) -> int:
    """Save scan results to database"""
    import json
    
    sqli_count = sum(1 for v in vulnerabilities if "SQL" in v.get("type", ""))
    xss_count = sum(1 for v in vulnerabilities if "XSS" in v.get("type", ""))
    info_count = sum(1 for v in vulnerabilities if "Sensitive" in v.get("type", ""))
    total_vulns = len(vulnerabilities)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans 
            (client_ip, target_url, scan_type, timestamp, vulns_json, 
             endpoints_count, sqli_count, xss_count, info_count, total_vulns)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (client_ip, target_url, scan_type, datetime.now(), 
              json.dumps(vulnerabilities), endpoints_count, 
              sqli_count, xss_count, info_count, total_vulns))
        conn.commit()
        return c.lastrowid

def get_all_scans(limit: int = 100) -> List[Dict]:
    """Retrieve all scans with optional limit"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, client_ip, target_url, scan_type, timestamp,
                   endpoints_count, sqli_count, xss_count, info_count, total_vulns
            FROM scans 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in c.fetchall()]

def get_scan_by_id(scan_id: int) -> Optional[Dict]:
    """Retrieve a specific scan with vulnerability details"""
    import json
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = c.fetchone()
        if row:
            result = dict(row)
            if result.get('vulns_json'):
                result['vulnerabilities'] = json.loads(result['vulns_json'])
            return result
    return None

def get_scan_stats() -> Dict:
    """Get aggregated statistics for all scans"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT 
                COUNT(*) as total_scans,
                COUNT(DISTINCT client_ip) as unique_clients,
                SUM(total_vulns) as total_vulnerabilities,
                SUM(sqli_count) as total_sqli,
                SUM(xss_count) as total_xss,
                SUM(info_count) as total_info,
                SUM(endpoints_count) as total_endpoints
            FROM scans
        """)
        row = c.fetchone()
        return dict(row) if row else {}

def get_scans_by_ip(client_ip: str) -> List[Dict]:
    """Get all scans from a specific client IP"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, client_ip, target_url, scan_type, timestamp,
                   endpoints_count, sqli_count, xss_count, info_count, total_vulns
            FROM scans 
            WHERE client_ip = ?
            ORDER BY timestamp DESC
        """, (client_ip,))
        return [dict(row) for row in c.fetchall()]

def get_recent_client_ips(limit: int = 50) -> List[Tuple[str, int]]:
    """Get recent unique client IPs with scan counts"""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT client_ip, COUNT(*) as scan_count
            FROM scans
            GROUP BY client_ip
            ORDER BY MAX(timestamp) DESC
            LIMIT ?
        """, (limit,))
        return [(row[0], row[1]) for row in c.fetchall()]

# Initialize database on import
if __name__ == "__main__":
    init_database()
    print("Database initialized successfully!")
    
    # Create default admin if none exists
    if not admin_exists():
        create_admin_user("admin", "admin123")
        print("Default admin user created (username: admin, password: admin123)")
    
    # Create initial API key if none exists
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM api_keys")
        if c.fetchone()[0] == 0:
            key = create_api_key()
            print(f"Initial API key created: {key}")
