import sqlite3
import bcrypt
import os

DB_NAME = "websec.db"

def init_db():
    """Initializes the SQLite database with the strict 3-table schema."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # 1. API Keys Table (For authorizing customer desktop app)
    c.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            active BOOLEAN DEFAULT 1
        )
    ''')

    # 2. Admin Users Table (For admin panel authentication)
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # 3. Scans Table (For logging scan results)
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT,
            target TEXT,
            vulns TEXT,
            metrics TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # --- Setup Default Data for Testing ---
    
    # Insert default API key if none exists
    c.execute("SELECT COUNT(*) FROM api_keys")
    if c.fetchone()[0] == 0:
        default_key = "default_api_key_12345"
        c.execute("INSERT INTO api_keys (key, active) VALUES (?, ?)", (default_key, 1))
        print(f"[*] Created default API key: {default_key}")

    # Insert default admin user if none exists
    c.execute("SELECT COUNT(*) FROM admin_users")
    if c.fetchone()[0] == 0:
        default_user = "admin"
        default_pass = "admin123"
        
        # Generate bcrypt hash
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(default_pass.encode('utf-8'), salt).decode('utf-8')
        
        c.execute("INSERT INTO admin_users (username, password_hash) VALUES (?, ?)", 
                  (default_user, hashed))
        print(f"[*] Created default Admin - User: {default_user} | Pass: {default_pass}")

    conn.commit()
    conn.close()
    print("[+] Database initialization complete.")

if __name__ == "__main__":
    init_db()