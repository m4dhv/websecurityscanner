import streamlit as st
import sqlite3
import database

# Must be the first streamlit command
st.set_page_config(
    page_title="WebSec Admin Panel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Session State Logic ────────────────────────────────────────────────────────
defaults = {
    "theme": "dark",
    "logged_in": False,
    "admin_user": None,
}

for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

is_dark = st.session_state.theme == "dark"

# ── Enhanced CSS with Theme Variables ──────────────────────────────────────────
st.markdown("""
<style>
h1 a, h2 a, [data-testid="stHeadingWithActionElements"] a {
    visibility: hidden; display: none !important;
}
</style>
""", unsafe_allow_html=True)

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap');

:root {{
    --bg:           {"#07090f" if is_dark else "#f8faff"};
    --surface:      {"#0d111c" if is_dark else "#ffffff"};
    --surface2:     {"#151926" if is_dark else "#f1f4ff"};
    --border:       {"#1e2540" if is_dark else "#e2e8f5"};
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
}}

html, body, [data-testid="stAppViewContainer"] {{
    background: var(--bg) !important; color: var(--text) !important;
    font-family: 'Syne', sans-serif !important; transition: all 0.3s ease;
}}

/* Clean up Streamlit UI */
[data-testid="stHeader"], [data-testid="stToolbar"], footer {{ display:none !important; }}
[data-testid="stAppViewContainer"] > .main > .block-container {{ padding: 2rem 5rem !important; max-width: 1200px !important; }}

/* Top Navigation */
.top-nav {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 3rem; }}
.logo-area {{ display: flex; align-items: center; gap: 12px; }}
.logo-box {{ width: 34px; height: 34px; background: var(--accent); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; box-shadow: 0 4px 15px var(--accent-bg); }}
.logo-text {{ font-weight: 800; font-size: 1.2rem; letter-spacing: -0.02em; }}
.logo-text span {{ color: var(--accent); }}

.status-pill {{ background: var(--surface2); border: 1px solid var(--border); padding: 6px 14px; border-radius: 100px; font-family: 'DM Mono', monospace; font-size: 0.7rem; color: var(--text2); display: flex; align-items: center; gap: 8px; }}
.dot {{ width: 8px; height: 8px; border-radius: 50%; }}
.dot-admin {{ background: var(--green); }}
.dot-lock {{ background: var(--red); }}

/* Input and Buttons */
[data-testid="stTextInput"] input {{ background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 12px !important; color: var(--text) !important; font-family: 'DM Mono', monospace !important; padding: 1.2rem !important; }}
[data-testid="stTextInput"] label {{ display: none !important; }}
[data-testid="stTextInput"] input::placeholder {{ color: var(--muted) !important; opacity: 0.8 !important; }}
[data-testid="InputInstructions"] {{ display: none !important; }}
[data-testid="stForm"] {{ border: none !important; padding: 0 !important; background: transparent !important; }}

button {{ border-radius: 25px !important; font-weight: 700 !important; text-transform: uppercase !important; letter-spacing: 0.05em !important; transition: all 0.2s !important; }}
button[kind="primary"], button[kind="primaryFormSubmit"] {{ background: var(--accent) !important; border: none !important; color: #fff !important; }}
button[kind="secondary"], button[kind="secondaryFormSubmit"] {{ background: var(--toggle) !important; border: 1px solid var(--border) !important; color: #fff !important; }}
</style>
""", unsafe_allow_html=True)

# ── Top Bar ──────────────────────────────────────────────────────────────────
status_display = "ADMIN ACTIVE" if st.session_state.logged_in else "LOCKED"
dot_class = "dot-admin" if st.session_state.logged_in else "dot-lock"

st.markdown(f"""
<div class="top-nav">
    <div class="logo-area">
        <div class="logo-box">🛡️</div>
        <div class="logo-text">Web<span>Sec</span> Admin</div>
    </div>
    <div style="display: flex; gap: 1rem; align-items: center;">
        <div class="status-pill"><div class="dot {dot_class}"></div>{status_display}</div>
    </div>
</div>
""", unsafe_allow_html=True)

# Main Header / Toggles
col_hl, col_out, col_tog = st.columns([0.7, 0.15, 0.15])
with col_hl:
    st.markdown("<p style='color: var(--accent); font-family: DM Mono; font-size: 0.7rem; font-weight: 600;'>SYSTEM ADMINISTRATION</p>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top: -10px; font-weight: 800;'>Global Dashboard</h1>", unsafe_allow_html=True)

with col_out:
    if st.session_state.logged_in:
        st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)
        if st.button("Logout", type="secondary", width="stretch"):
            st.session_state.logged_in = False
            st.session_state.admin_user = None
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
        with st.form("admin_login", clear_on_submit=False):
            st.markdown("<h2 style='text-align: center;'>Admin Gateway</h2>", unsafe_allow_html=True)
            st.markdown("<p style='text-align: center; color: var(--muted); margin-bottom: 30px;'>Enter admin credentials to view system logs</p>", unsafe_allow_html=True)
            
            username = st.text_input("Username", placeholder="Admin Username", key="a_usr")
            password = st.text_input("Password", placeholder="Password", type="password", key="a_pwd")
            
            st.markdown("<br>", unsafe_allow_html=True)
            if st.form_submit_button("Authenticate", type="primary", width="stretch"):
                if database.verify_admin_password(username, password):
                    st.session_state.logged_in = True
                    st.session_state.admin_user = username
                    st.rerun()
                else:
                    st.error("Invalid admin credentials.")
                    
    st.markdown(f"""
    <div style="margin-top: 4rem; padding: 2rem; border-top: 1px solid var(--border); text-align: center; color: var(--muted); font-family: DM Mono; font-size: 0.65rem;">
        ⚠️ SECURE FACILITY &nbsp; • &nbsp; AUTHORIZED ADMINS ONLY
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ── Admin Dashboard (Logs Only) ────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.subheader("Global Scan Logs")

# Connect using standard sqlite3 to pull data manually since database.py 
# helper functions don't pull all the columns we might want for a full table view.
conn = sqlite3.connect("websec.db")
c = conn.cursor()

# Query mapping to the new schema in database.py
c.execute("""
    SELECT 
        s.id, 
        s.client_ip, 
        s.target_url, 
        s.scan_type, 
        s.status,
        s.started_at, 
        s.endpoints_count, 
        s.total_vulns, 
        s.sqli_count, 
        s.xss_count, 
        s.info_count
    FROM scans s
    ORDER BY s.started_at DESC
""")
scan_rows = c.fetchall()

if scan_rows:
    scan_data = [
        {
            "Log ID": r[0],
            "Client IP": r[1],
            "Target": r[2],
            "Mode": r[3].capitalize(),
            "Status": r[4].upper(),
            "Time (UTC)": r[5],
            "Endpoints": r[6],
            "Total Issues": r[7],
            "SQLi (Critical)": r[8],
            "XSS (High)": r[9],
            "Info (Medium)": r[10],
        }
        for r in scan_rows
    ]
    st.dataframe(scan_data, width="stretch")
else:
    st.info("No scans have been executed on the network yet.")

conn.close()

# Footer
st.markdown(f"""
<div style="margin-top: 4rem; padding: 2rem; border-top: 1px solid var(--border); text-align: center; color: var(--muted); font-family: DM Mono; font-size: 0.65rem;">
    ⚠️ AUTHORIZED USE ONLY &nbsp; • &nbsp; COMPLIANCE REQUIRED &nbsp; • &nbsp; WEBSEC ENGINE V2.5
</div>
""", unsafe_allow_html=True)