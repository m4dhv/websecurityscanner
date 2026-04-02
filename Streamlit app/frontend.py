import streamlit as st
import io
import time
import sqlite3
import hashlib
import json
import re
from datetime import datetime
from contextlib import redirect_stdout
from scanner import WebSecurityScanner

# Must be the first streamlit command
st.set_page_config(
    page_title="WebSec Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ── Database Initialization ───────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("websec.db")
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    role TEXT
                )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    target_url TEXT,
                    scan_type TEXT,
                    timestamp DATETIME,
                    vulns_json TEXT,
                    endpoints_count INTEGER,
                    sqli_count INTEGER,
                    xss_count INTEGER,
                    info_count INTEGER,
                    total_vulns INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )"""
    )
    # Create default admin if not exists
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        admin_hash = hashlib.sha256(b"admin").hexdigest()
        c.execute(
            "INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)",
            ("admin@websec.local", "admin", admin_hash, "admin"),
        )
    conn.commit()
    conn.close()


init_db()


def hash_pass(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ── Session State Logic ────────────────────────────────────────────────────────
defaults = {
    "theme": "dark",
    "status": "IDLE",
    "vulns": [],
    "urls_cnt": 0,
    "scan_done": False,
    "target_url": "",
    "scan_type": None,
    "logged_in": False,
    "auth_mode": "login",
    "user_id": None,
    "role": "user",
    "view": "scanner",
}

for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

is_dark = st.session_state.theme == "dark"

# ── Enhanced CSS with Theme Variables ──────────────────────────────────────────
st.markdown(
    """
<style>
h1 a {
    visibility: hidden;
}
h2 a {
    visibility: hidden;
}
</style>
""",
    unsafe_allow_html=True,
)
st.markdown(
    f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap');

:root {{
    --bg:           {"#07090f" if is_dark else "#f8faff"};
    --surface:      {"#0d111c" if is_dark else "#ffffff"};
    --surface2:     {"#151926" if is_dark else "#f1f4ff"};
    --border:       {"#1e2540" if is_dark else "#e2e8f5"};
    --border2:      {"#2a334f" if is_dark else "#cbd5e1"};
    --text:         {"#e8ecf4" if is_dark else "#0f172a"};
    --text2:        {"#9ba3be" if is_dark else "#475569"};
    --muted:        {"#5a6480" if is_dark else "#71717a"};
    --accent:       {"#22C55E" if is_dark else "#0d7e0f"};
    --accent-bg:    {"rgba(79,124,255,0.1)" if is_dark else "rgba(37,99,235,0.08)"};
    --red:          #ff4d6d;
    --orange:       #ffa94d;
    --yellow:       #ffd54d;
    --green:        #22c55e;
    --toggle:       #5a6480;
    --card-shadow:  {"0 8px 30px rgba(0,0,0,0.4)" if is_dark else "0 4px 20px rgba(0,0,0,0.05)"};
}}

html, body, [data-testid="stAppViewContainer"] {{
    background: var(--bg) !important; color: var(--text) !important;
    font-family: 'Syne', sans-serif !important; transition: all 0.3s ease;
}}

/* Clean up Streamlit UI */
[data-testid="stHeader"], [data-testid="stToolbar"], footer {{ display:none !important; }}
[data-testid="stAppViewContainer"] > .main > .block-container {{ padding: 2rem 5rem !important; max-width: 1000px !important; }}

/* Top Navigation */
.top-nav {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 3rem; }}
.logo-area {{ display: flex; align-items: center; gap: 12px; }}
.logo-box {{ width: 34px; height: 34px; background: var(--accent); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; box-shadow: 0 4px 15px var(--accent-bg); }}
.logo-text {{ font-weight: 800; font-size: 1.2rem; letter-spacing: -0.02em; }}
.logo-text span {{ color: var(--accent); }}

.status-pill {{ background: var(--surface2); border: 1px solid var(--border); padding: 6px 14px; border-radius: 100px; font-family: 'DM Mono', monospace; font-size: 0.7rem; color: var(--text2); display: flex; align-items: center; gap: 8px; }}
.dot {{ width: 8px; height: 8px; border-radius: 50%; }}
.dot-idle {{ background: var(--green); }}
.dot-scan {{ background: var(--orange); animation: pulse 1s infinite; }}
.dot-lock {{ background: var(--red); }}

@keyframes pulse {{ 0%{{opacity:1}} 50%{{opacity:0.3}} 100%{{opacity:1}} }}

/* Metric Cards */
.metrics-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2.5rem; }}
.m-card {{ background: var(--surface); border: 1px solid var(--border); padding: 1.5rem; border-radius: 16px; box-shadow: var(--card-shadow); transition: transform 0.2s ease; }}
.m-card:hover {{ transform: translateY(-3px); border-color: var(--accent); }}
.m-label {{ color: var(--muted); font-size: 0.65rem; text-transform: uppercase; font-family: 'DM Mono', monospace; letter-spacing: 0.1em; }}
.m-val {{ font-size: 2.2rem; font-weight: 800; margin-top: 5px; }}

/* Input and Buttons */
[data-testid="stTextInput"] input {{ background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 12px !important; color: var(--text) !important; font-family: 'DM Mono', monospace !important; padding: 1.2rem !important; }}
[data-testid="stTextInput"] label {{ display: none !important; }}
[data-testid="stTextInput"] input::placeholder {{ color: var(--muted) !important; opacity: 0.8 !important; }}

/* Hide 'Press Enter to apply' text */
[data-testid="InputInstructions"] {{ display: none !important; }}

/* Remove default styling from Streamlit forms */
[data-testid="stForm"] {{ border: none !important; padding: 0 !important; background: transparent !important; }}

button {{ border-radius: 25px !important; font-weight: 700 !important; text-transform: uppercase !important; letter-spacing: 0.05em !important; transition: all 0.2s !important; }}
button[kind="primary"], button[kind="primaryFormSubmit"] {{ background: var(--accent) !important; border: none !important; color: #fff !important; }}
button[kind="secondary"], button[kind="secondaryFormSubmit"] {{ background: var(--toggle) !important; border: 1px solid var(--border) !important; color: #fff !important; }}

/* Custom Rounded Black Toggle Button Styling */
div[data-testid="stHorizontalBlock"]:first-of-type div[data-testid="column"]:nth-child(3) button {{ background-color: #000000 !important; color: #ffffff !important; border: 1px solid #333333 !important; border-radius: 50% !important; width: 45px !important; height: 45px !important; padding: 0 !important; display: flex !important; align-items: center !important; justify-content: center !important; margin-left: auto !important; box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important; }}
div[data-testid="stHorizontalBlock"]:first-of-type div[data-testid="column"]:nth-child(3) button:hover {{ border-color: var(--accent) !important; transform: scale(1.1) !important; }}

/* Expanders for Findings */
.stExpander {{ background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 12px !important; margin-bottom: 0.5rem !important; }}
.f-tag {{ font-family: 'DM Mono', monospace; font-size: 0.6rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; margin-right: 10px; text-transform: uppercase; }}
.stExpander summary {{ background: var(--surface2) !important; border: 1px solid var(--border) !important; border-radius: 12px !important; margin-bottom: 0.5rem !important; }}

/* NEW: Added .tag-med for Medium Severity */
.tag-crit {{ background: rgba(255,77,109,0.15); color: var(--red); }}
.tag-high {{ background: rgba(255,169,77,0.15); color: var(--orange); }}
.tag-med  {{ background: rgba(255,213,77,0.15); color: var(--yellow); }}

.detail-row {{ display: grid; grid-template-columns: 100px 1fr; gap: 10px; font-size: 0.8rem; margin: 4px 0; }}
.detail-k {{ color: var(--muted); font-family: 'DM Mono', monospace; }}
.detail-v {{ color: var(--text2); font-family: 'DM Mono', monospace; word-break: break-all; }}

/* Hide heading anchor links */
[data-testid="stHeadingWithActionElements"] a {{ display: none !important; }}
</style>
""",
    unsafe_allow_html=True,
)

# Determine Top Nav Status Display
if not st.session_state.logged_in:
    status_display = "LOCKED"
    dot_class = "dot-lock"
else:
    status_display = st.session_state.status
    dot_class = "dot-scan" if st.session_state.status == "SCANNING" else "dot-idle"

# ── Top Bar ──────────────────────────────────────────────────────────────────
st.markdown(
    f"""
<div class="top-nav">
    <div class="logo-area">
        <div class="logo-box">🛡️</div>
        <div class="logo-text">Web<span>Sec</span></div>
    </div>
    <div style="display: flex; gap: 1rem; align-items: center;">
        <div class="status-pill"><div class="dot {dot_class}"></div>{status_display}</div>
    </div>
</div>
""",
    unsafe_allow_html=True,
)

# ── Main Header ────────────────────────────────────────────────────────────────
col_hl, col_out, col_tog = st.columns([0.7, 0.15, 0.15])
with col_hl:
    st.markdown(
        f"<p style='color: var(--accent); font-family: DM Mono; font-size: 0.7rem; font-weight: 600;'>AUTOMATED SECURITY AUDIT</p>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<h1 style='margin-top: -10px; font-weight: 800;'>Website Security Scanner</h1>",
        unsafe_allow_html=True,
    )

with col_out:
    if st.session_state.logged_in:
        st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)
        if st.button("Logout", type="secondary", width="stretch"):
            for k in ["logged_in", "user_id", "role"]:
                st.session_state[k] = defaults[k]
            st.session_state.status = "IDLE"
            st.session_state.view = "scanner"
            st.rerun()

with col_tog:
    st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)
    if st.button("☀️" if is_dark else "🌙", type="secondary"):
        st.session_state.theme = "light" if is_dark else "dark"
        st.rerun()

# ── Authentication Gate ───────────────────────────────────────────────────────
if not st.session_state.logged_in:
    st.markdown("<br><br>", unsafe_allow_html=True)
    _, col_auth, _ = st.columns([1, 1.2, 1])

    with col_auth:
        if st.session_state.auth_mode == "login":
            with st.form("login_form", clear_on_submit=False):
                st.markdown(
                    "<h2 style='text-align: center;'>Log In</h2>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    "<p style='text-align: center; color: var(--muted); margin-bottom: 30px;'>Enter your credentials to continue</p>",
                    unsafe_allow_html=True,
                )

                user_input = st.text_input(
                    "Username or Email", placeholder="Username or Email", key="l_usr"
                )
                pass_input = st.text_input(
                    "Password", placeholder="Password", type="password", key="l_pwd"
                )

                st.markdown("<br>", unsafe_allow_html=True)
                submitted = st.form_submit_button(
                    "Login", type="primary", width="stretch"
                )

                if submitted:
                    conn = sqlite3.connect("websec.db")
                    c = conn.cursor()
                    c.execute(
                        "SELECT id, role FROM users WHERE (email=? OR username=?) AND password_hash=?",
                        (user_input, user_input, hash_pass(pass_input)),
                    )
                    user = c.fetchone()
                    conn.close()

                    if user:
                        st.session_state.logged_in = True
                        st.session_state.user_id = user[0]
                        st.session_state.role = user[1]
                        st.rerun()
                    else:
                        st.error("Invalid credentials.")

            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("sign up", type="secondary", width="stretch"):
                st.session_state.auth_mode = "register"
                st.rerun()

        else:
            with st.form("register_form", clear_on_submit=False):
                st.markdown(
                    "<h2 style='text-align: center;'>Create New Account</h2>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    "<p style='text-align: center; color: var(--muted); margin-bottom: 30px;'>Sign up with a new account to access the application.</p>",
                    unsafe_allow_html=True,
                )

                new_email = st.text_input(
                    "Email", placeholder="Email Address", key="r_email"
                )
                new_user = st.text_input(
                    "Username", placeholder="New Username", key="r_usr"
                )
                new_pass = st.text_input(
                    "Password", placeholder="New Password", type="password", key="r_pwd"
                )
                conf_pass = st.text_input(
                    "Confirm",
                    placeholder="Confirm Password",
                    type="password",
                    key="r_conf",
                )

                st.markdown("<br>", unsafe_allow_html=True)
                submitted = st.form_submit_button(
                    "Sign Up", type="primary", width="stretch"
                )

                if submitted:
                    if new_pass != conf_pass:
                        st.error("Passphrases do not match.")
                    elif len(new_user) < 3 or len(new_pass) < 3:
                        st.error("Requires minimum 3 characters.")
                    else:
                        try:
                            conn = sqlite3.connect("websec.db")
                            c = conn.cursor()
                            c.execute(
                                "INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)",
                                (new_email, new_user, hash_pass(new_pass), "user"),
                            )
                            conn.commit()
                            st.success("ID registered. Please use it for login.")
                            time.sleep(1.5)
                            st.session_state.auth_mode = "login"
                            st.rerun()
                        except sqlite3.IntegrityError:
                            st.error(
                                "Email or Username already exists in the database."
                            )
                        finally:
                            conn.close()

            st.markdown("<br>", unsafe_allow_html=True)
            if st.button(
                "Have an ID ? Go back to Login", type="secondary", width="stretch"
            ):
                st.session_state.auth_mode = "login"
                st.rerun()

    st.markdown(
        f"""
    <div style="margin-top: 4rem; padding: 2rem; border-top: 1px solid var(--border); text-align: center; color: var(--muted); font-family: DM Mono; font-size: 0.65rem;">
        ⚠️ AUTHORIZED USE ONLY &nbsp; • &nbsp; COMPLIANCE REQUIRED &nbsp; • &nbsp; WEBSEC ENGINE V2.5
    </div>
    """,
        unsafe_allow_html=True,
    )
    st.stop()

# ── Admin Panel Toggle ────────────────────────────────────────────────────────
if st.session_state.role == "admin":
    view_label = (
        "Return to Scanner"
        if st.session_state.view == "admin"
        else "⚙️ Access Admin Panel"
    )
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button(view_label, type="secondary", width="stretch"):
        st.session_state.view = (
            "admin" if st.session_state.view == "scanner" else "scanner"
        )
        st.rerun()

# ── Admin View ────────────────────────────────────────────────────────────────
if st.session_state.view == "admin":
    st.subheader("Global Scan Logs")
    conn = sqlite3.connect("websec.db")
    c = conn.cursor()

    c.execute(
        """SELECT s.id, u.username, s.target_url, s.scan_type, s.timestamp, s.endpoints_count, 
                        s.total_vulns, s.sqli_count, s.xss_count, s.info_count
                 FROM scans s JOIN users u ON s.user_id = u.id ORDER BY s.timestamp DESC"""
    )
    scan_rows = c.fetchall()

    if scan_rows:
        scan_data = [
            {
                "Log ID": r[0],
                "User": r[1],
                "Target": r[2],
                "Mode": r[3],
                "Time": r[4],
                "Endpoints": r[5],
                "Total Issues": r[6],
                "SQLi (Critical)": r[7],
                "XSS (High)": r[8],
                "Info (Medium)": r[9],
            }
            for r in scan_rows
        ]
        st.dataframe(scan_data, width="stretch")
    else:
        st.info("No scans have been performed yet.")

    st.markdown("<br><br>", unsafe_allow_html=True)

    st.subheader("Registered Users Directory")
    c.execute("SELECT id, username, email, role FROM users ORDER BY id ASC")
    user_rows = c.fetchall()

    if user_rows:
        user_data = [
            {
                "User ID": r[0],
                "Username": r[1],
                "Email": r[2],
                "System Role": r[3].capitalize(),
            }
            for r in user_rows
        ]
        st.dataframe(user_data, width="stretch")
    else:
        st.info("No users found.")

    conn.close()

    st.markdown(
        f"""
    <div style="margin-top: 4rem; padding: 2rem; border-top: 1px solid var(--border); text-align: center; color: var(--muted); font-family: DM Mono; font-size: 0.65rem;">
        ⚠️ AUTHORIZED USE ONLY &nbsp; • &nbsp; COMPLIANCE REQUIRED &nbsp; • &nbsp; WEBSEC ENGINE V2.5
    </div>
    """,
        unsafe_allow_html=True,
    )
    st.stop()


# ── Main UI (Scanner) ─────────────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)

target_url = st.text_input(
    "Target URL",
    value=st.session_state.target_url,
    placeholder="enter URL of target website here",
)

# Create three columns to act as a wrapper for centering
_, col_btn_center, _ = st.columns([1, 2, 1])

with col_btn_center:
    # Create a 2-column grid inside the middle column to keep buttons side-by-side
    sub_col1, sub_col2 = st.columns(2)
    with sub_col1:
        quick_btn = st.button("⚡ Quick Scan", type="primary", width="stretch")
    with sub_col2:
        deep_btn = st.button("🕷 Deep Scan", type="primary", width="stretch")

# ── Scan Execution (Update this section) ──────────────────────────────────────
if quick_btn or deep_btn:
    # 1. Strip whitespace
    clean_url = target_url.strip()

    # 2. Validate URL: must be localhost (with optional port/path) OR a proper domain with a dot.
    # Anchored correctly so bare strings like "sdsds" never match.
    url_pattern = re.compile(
        r"^(https?://)?(localhost|([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(:\d{1,5})?(/[^\s]*)?$",
        re.IGNORECASE,
    )

    if not clean_url:
        st.error("Target URL cannot be empty.")
    elif not url_pattern.match(clean_url):
        st.error(f"'{clean_url}' is not a valid target. Please enter a valid URL.")
    else:
        st.session_state.target_url = clean_url
        st.session_state.status = "SCANNING"
        st.session_state.scan_type = "quick" if quick_btn else "deep"
        st.rerun()

if st.session_state.status == "SCANNING":
    url = st.session_state.target_url
    if not url.startswith("http"):
        url = "http://" + url  # Default to http for localhost compatibility

    with st.status("🔍 Analyzing target architecture...", expanded=True) as status:
        scanner = WebSecurityScanner(url, max_depth=3)
        try:
            # We use io.StringIO to capture the "print" statements from scanner.py
            f = io.StringIO()
            with redirect_stdout(f):
                if st.session_state.scan_type == "quick":
                    vulns = scanner.quickscan()
                else:
                    vulns = scanner.deepscan()

            # Check if there were any errors printed to stdout
            scan_output = f.getvalue()
            if "Error" in scan_output:
                st.warning("Scan completed with network errors (see below).")
                st.code(
                    scan_output
                )  # Shows the exact "No scheme supplied" or connection errors

            st.session_state.vulns = vulns
            st.session_state.urls_cnt = len(scanner.visited_urls)
            st.session_state.scan_done = True
            st.session_state.status = "IDLE"

            # Save results to Database
            sql_cnt = sum(1 for v in vulns if "SQL" in v.get("type", ""))
            xss_cnt = sum(1 for v in vulns if "XSS" in v.get("type", ""))
            info_cnt = sum(1 for v in vulns if "Sensitive" in v.get("type", ""))

            conn = sqlite3.connect("websec.db")
            c = conn.cursor()
            c.execute(
                """INSERT INTO scans 
                         (user_id, target_url, scan_type, timestamp, vulns_json, endpoints_count, sqli_count, xss_count, info_count, total_vulns) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    st.session_state.user_id,
                    url,
                    st.session_state.scan_type,
                    datetime.now(),
                    json.dumps(vulns),
                    st.session_state.urls_cnt,
                    sql_cnt,
                    xss_cnt,
                    info_cnt,
                    len(vulns),
                ),
            )
            conn.commit()
            conn.close()

            status.update(label="Scan complete!", state="complete", expanded=False)
            time.sleep(1.0)
            st.rerun()
        except Exception as e:
            st.error(f"Critical System Error: {str(e)}")
            st.session_state.status = "IDLE"
            st.rerun()

# ── Dashboard & Results ───────────────────────────────────────────────────────
vulns = st.session_state.vulns
sql_cnt = sum(1 for v in vulns if "SQL" in v.get("type", ""))
xss_cnt = sum(1 for v in vulns if "XSS" in v.get("type", ""))
info_cnt = sum(1 for v in vulns if "Sensitive" in v.get("type", ""))

st.markdown(
    f"""
<div class="metrics-row">
    <div class="m-card"><div class="m-label">Endpoints</div><div class="m-val" style="color: var(--text)">{st.session_state.urls_cnt}</div></div>
    <div class="m-card"><div class="m-label">Critical (SQLi)</div><div class="m-val" style="color: var(--red)">{sql_cnt}</div></div>
    <div class="m-card"><div class="m-label">High (XSS)</div><div class="m-val" style="color: var(--orange)">{xss_cnt}</div></div>
    <div class="m-card"><div class="m-label">Medium (Info Leak)</div><div class="m-val" style="color: var(--yellow)">{info_cnt}</div></div>
</div>
""",
    unsafe_allow_html=True,
)

st.subheader("Security Findings")

if not st.session_state.scan_done:
    st.info(
        "No active scan results. Enter a target URL and choose a scan mode to begin."
    )
elif not vulns:
    st.success("Target surface appears clean. No vulnerabilities detected.")
else:
    for i, v in enumerate(vulns):
        v_type = v.get("type", "Unknown Issue")
        v_url = v.get("url", "Unknown Source")

        # NEW: 3-Tier Logic for tags
        if "SQL" in v_type:
            sev_class, sev_text = "tag-crit", "CRITICAL"
        elif "XSS" in v_type:
            sev_class, sev_text = "tag-high", "HIGH"
        else:
            sev_class, sev_text = "tag-med", "MEDIUM"

        tag_html = f"<span class='f-tag {sev_class}'>{sev_text}</span>"

        with st.expander(f"{v_type} — {v_url[:60]}..."):
            st.markdown(tag_html, unsafe_allow_html=True)
            st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
            for key, val in v.items():
                if key == "type":
                    continue
                is_payload = key in ["payload", "pattern", "parameter"]
                st.markdown(
                    f"""
                <div class="detail-row">
                    <div class="detail-k">{key.upper()}</div>
                    <div class="detail-v" style="color: {'var(--orange)' if is_payload else 'inherit'}">{val}</div>
                </div>
                """,
                    unsafe_allow_html=True,
                )

st.markdown(
    f"""
<div style="margin-top: 4rem; padding: 2rem; border-top: 1px solid var(--border); text-align: center; color: var(--muted); font-family: DM Mono; font-size: 0.65rem;">
    ⚠️ AUTHORIZED USE ONLY &nbsp; • &nbsp; COMPLIANCE REQUIRED &nbsp; • &nbsp; WEBSEC ENGINE V2.5
</div>
""",
    unsafe_allow_html=True,
)
