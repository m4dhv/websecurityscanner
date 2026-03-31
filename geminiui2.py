import streamlit as st
import io
import time
import sqlite3
import hashlib
import json
from datetime import datetime
from contextlib import redirect_stdout
from scanner import WebSecurityScanner

st.set_page_config(page_title="WebSec Scanner", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

# ── Database Initialization ───────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("websec.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    role TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    target_url TEXT,
                    scan_type TEXT,
                    timestamp DATETIME,
                    vulns_json TEXT,
                    endpoints_count INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    # Create default admin if not exists
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        admin_hash = hashlib.sha256(b"admin").hexdigest()
        c.execute("INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)",
                  ("admin@websec.local", "admin", admin_hash, "admin"))
    conn.commit()
    conn.close()

init_db()

def hash_pass(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ── Session State Logic ───────────────────────────────────────────────────────
defaults = {
    "theme": "dark", "status": "IDLE", "vulns": [], "urls_cnt": 0,
    "scan_done": False, "target_url": "", "scan_type": None,
    "logged_in": False, "auth_mode": "login", "user_id": None, 
    "role": "user", "view": "scanner"
}
for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

is_dark = st.session_state.theme == "dark"

# (Keep your existing CSS Block Here. I've omitted the raw string purely for brevity in this response to focus on the logic, but leave your st.markdown("<style>...</style>") exactly as you wrote it).

# Determine Top Nav Status Display
status_display = "LOCKED" if not st.session_state.logged_in else st.session_state.status
dot_class = 'dot-scan' if st.session_state.status == 'SCANNING' else ('dot-lock' if not st.session_state.logged_in else 'dot-idle')

st.markdown(f"""
<div class="top-nav">
    <div class="logo-area">
        <div class="logo-box">🛡️</div>
        <div class="logo-text">Web<span>Sec</span></div>
    </div>
    <div style="display: flex; gap: 1rem; align-items: center;">
        <div class="status-pill"><div class="dot {dot_class}"></div>{status_display}</div>
    </div>
</div>
""", unsafe_allow_html=True)

# Header & Controls
col_hl, col_out, col_tog = st.columns([0.7, 0.15, 0.15])
with col_hl:
    st.markdown("<h1 style='font-weight: 800;'>Website Security Scanner</h1>", unsafe_allow_html=True)
with col_out:
    if st.session_state.logged_in:
        if st.button("Logout", use_container_width=True):
            for k in ["logged_in", "user_id", "role"]: st.session_state[k] = defaults[k]
            st.rerun()
with col_tog:
    if st.button("☀️" if is_dark else "🌙"):
        st.session_state.theme = "light" if is_dark else "dark"
        st.rerun()

# ── Authentication Gate ───────────────────────────────────────────────────────
if not st.session_state.logged_in:
    _, col_auth, _ = st.columns([1, 1.2, 1])
    with col_auth:
        if st.session_state.auth_mode == "login":
            st.markdown("<h2 style='text-align: center;'>System Access</h2>", unsafe_allow_html=True)
            user_input = st.text_input("Username or Email", key="l_usr")
            pass_input = st.text_input("Password", type="password", key="l_pwd")
            
            if st.button("Authenticate", type="primary", use_container_width=True):
                conn = sqlite3.connect("websec.db")
                c = conn.cursor()
                c.execute("SELECT id, role FROM users WHERE (email=? OR username=?) AND password_hash=?", 
                          (user_input, user_input, hash_pass(pass_input)))
                user = c.fetchone()
                conn.close()
                
                if user:
                    st.session_state.logged_in = True
                    st.session_state.user_id = user[0]
                    st.session_state.role = user[1]
                    st.rerun()
                else:
                    st.error("Invalid credentials.")
            
            if st.button("Request Access (Register)", use_container_width=True):
                st.session_state.auth_mode = "register"
                st.rerun()
                
        else:
            st.markdown("<h2 style='text-align: center;'>Request Access</h2>", unsafe_allow_html=True)
            new_email = st.text_input("Email", key="r_email")
            new_user = st.text_input("Username", key="r_usr")
            new_pass = st.text_input("Password", type="password", key="r_pwd")
            conf_pass = st.text_input("Confirm", type="password", key="r_conf")
            
            if st.button("Register Identity", type="primary", use_container_width=True):
                if new_pass != conf_pass:
                    st.error("Passphrases do not match.")
                elif len(new_user) < 3 or len(new_pass) < 3:
                    st.error("Requires minimum 3 characters.")
                else:
                    try:
                        conn = sqlite3.connect("websec.db")
                        c = conn.cursor()
                        c.execute("INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)", 
                                  (new_email, new_user, hash_pass(new_pass), "user"))
                        conn.commit()
                        st.success("Identity registered. Please authenticate.")
                        time.sleep(1.5)
                        st.session_state.auth_mode = "login"
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("Email or Username already exists.")
                    finally:
                        conn.close()
                        
            if st.button("Back to Login", use_container_width=True):
                st.session_state.auth_mode = "login"
                st.rerun()
    st.stop()

# ── Admin Panel Toggle ────────────────────────────────────────────────────────
if st.session_state.role == "admin":
    view_label = "Return to Scanner" if st.session_state.view == "admin" else "⚙️ Admin Panel"
    if st.button(view_label, use_container_width=True):
        st.session_state.view = "admin" if st.session_state.view == "scanner" else "scanner"
        st.rerun()

# ── Admin View ────────────────────────────────────────────────────────────────
if st.session_state.view == "admin":
    st.subheader("Admin Dashboard: Global Scan Logs")
    conn = sqlite3.connect("websec.db")
    c = conn.cursor()
    c.execute("""SELECT s.id, u.username, s.target_url, s.scan_type, s.timestamp, s.endpoints_count 
                 FROM scans s JOIN users u ON s.user_id = u.id ORDER BY s.timestamp DESC""")
    rows = c.fetchall()
    conn.close()
    
    if rows:
        data = [{"ID": r[0], "User": r[1], "Target": r[2], "Type": r[3], "Time": r[4], "Endpoints": r[5]} for r in rows]
        st.dataframe(data, use_container_width=True)
    else:
        st.info("No scans have been performed yet.")
    st.stop()

# ── Main UI (Scanner) ─────────────────────────────────────────────────────────
target_url = st.text_input("Target URL", value=st.session_state.target_url)

col_q, col_d, _ = st.columns([1, 1, 2])
with col_q:
    quick_btn = st.button("⚡ Quick Scan", type="primary", use_container_width=True)
with col_d:
    deep_btn = st.button("🕷 Deep Scan", type="primary", use_container_width=True)

if quick_btn or deep_btn:
    if not target_url.strip():
        st.error("Please provide a valid URL.")
    else:
        st.session_state.target_url = target_url
        st.session_state.status = "SCANNING"
        st.session_state.scan_type = "quick" if quick_btn else "deep" 
        st.rerun()

if st.session_state.status == "SCANNING":
    url = st.session_state.target_url
    if not url.startswith("http"): url = "https://" + url
    
    with st.status("🔍 Analyzing target architecture...", expanded=True) as status:
        scanner = WebSecurityScanner(url, max_depth=3)
        f = io.StringIO()
        with redirect_stdout(f):
            vulns = scanner.quickscan() if st.session_state.scan_type == "quick" else scanner.deepscan()
            
        st.session_state.vulns = vulns
        st.session_state.urls_cnt = len(scanner.visited_urls)
        st.session_state.scan_done = True
        st.session_state.status = "IDLE"
        
        # Save to SQLite DB
        conn = sqlite3.connect("websec.db")
        c = conn.cursor()
        c.execute("INSERT INTO scans (user_id, target_url, scan_type, timestamp, vulns_json, endpoints_count) VALUES (?, ?, ?, ?, ?, ?)",
                  (st.session_state.user_id, url, st.session_state.scan_type, datetime.now(), json.dumps(vulns), st.session_state.urls_cnt))
        conn.commit()
        conn.close()

        status.update(label="Scan complete!", state="complete", expanded=False)
        time.sleep(0.5)
        st.rerun()

# ── Dashboard & Results ───────────────────────────────────────────────────────
vulns = st.session_state.vulns
sql_cnt = sum(1 for v in vulns if "SQL" in v.get("type", ""))
xss_cnt = sum(1 for v in vulns if "XSS" in v.get("type", ""))
info_cnt = sum(1 for v in vulns if "Sensitive" in v.get("type", ""))

st.markdown(f"""
<div class="metrics-row">
    <div class="m-card"><div class="m-label">Endpoints</div><div class="m-val">{st.session_state.urls_cnt}</div></div>
    <div class="m-card"><div class="m-label">Critical (SQLi)</div><div class="m-val" style="color:var(--red)">{sql_cnt}</div></div>
    <div class="m-card"><div class="m-label">High (XSS)</div><div class="m-val" style="color:var(--orange)">{xss_cnt}</div></div>
    <div class="m-card"><div class="m-label">Medium</div><div class="m-val" style="color:var(--yellow)">{info_cnt}</div></div>
</div>
""", unsafe_allow_html=True)

st.subheader("Security Findings")

if not st.session_state.scan_done:
    st.info("No active scan results. Enter a target URL and choose a scan mode to begin.")
elif not vulns:
    st.success("Target surface appears clean. No vulnerabilities detected.")
else:
    for i, v in enumerate(vulns):
        v_type = v.get("type", "Unknown Issue")
        is_crit = "SQL" in v_type
        tag_html = f"<span class='f-tag {'tag-crit' if is_crit else 'tag-high'}'>{'CRITICAL' if is_crit else 'HIGH'}</span>"
        
        with st.expander(f"{v_type} — {v.get('url', '')[:60]}..."):
            st.markdown(tag_html, unsafe_allow_html=True)
            for key, val in v.items():
                if key == "type": continue
                st.markdown(f"**{key.upper()}**: `{val}`")