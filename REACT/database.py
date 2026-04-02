import sqlite3
import bcrypt
import os

DB_NAME = "websec_prod.db"

def get_db_connection():
    """Creates and returns a database connection with dictionary-like row access."""
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the SQLite database with strictly 3 tables."""
    conn = get_db_connection()
    c = conn.cursor()

    # 1. API Keys Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            active INTEGER DEFAULT 1
        )
    ''')

    # 2. Admin Users Table (No customer login table)
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # 3. Scans Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip TEXT NOT NULL,
            target TEXT NOT NULL,
            vulns TEXT NOT NULL, -- Stored as JSON string
            metrics TEXT NOT NULL, -- Stored as JSON string
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed Default Admin if table is empty
    c.execute("SELECT id FROM admin_users WHERE username='admin'")
    if not c.fetchone():
        # Default password is 'admin' (Change in production)
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(b"admin", salt).decode('utf-8')
        c.execute(
            "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
            ("admin", hashed_pw)
        )
        print("Default admin user created.")

    # Seed a default API Key for immediate testing
    c.execute("SELECT id FROM api_keys")
    if not c.fetchone():
        c.execute(
            "INSERT INTO api_keys (key, active) VALUES (?, ?)",
            ("sk_dev_9948274619", 1)
        )
        print("Default dev API key created: sk_dev_9948274619")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print(f"Database schema initialized successfully at {DB_NAME}.")