
import streamlit as st
import io
import re
import time
from contextlib import redirect_stdout
from scanner import WebSecurityScanner

# Must be the first streamlit command
st.set_page_config(
    page_title="WebSec Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Session State Logic ────────────────────────────────────────────────────────
defaults = {
    "theme": "dark",
    "status": "IDLE",
    "vulns": [],
    "urls_cnt": 0,
    "scan_done": False,
    "target_url": "",
    "scan_type": None  # Added to track which button was pressed
}

for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

is_dark = st.session_state.theme == "dark"

# ── Enhanced CSS with Theme Variables ──────────────────────────────────────────
st.markdown(f"""
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
    --toggle:        #5a6480;
    --card-shadow:  {"0 8px 30px rgba(0,0,0,0.4)" if is_dark else "0 4px 20px rgba(0,0,0,0.05)"};
}}

html, body, [data-testid="stAppViewContainer"] {{
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: 'Syne', sans-serif !important;
    transition: all 0.3s ease;
}}

/* Clean up Streamlit UI */
[data-testid="stHeader"], [data-testid="stToolbar"], footer {{ display:none !important; }}
[data-testid="stAppViewContainer"] > .main > .block-container {{
    padding: 2rem 5rem !important;
    max-width: 1000px !important;
}}

/* Top Navigation */
.top-nav {{
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 3rem;
}}
.logo-area {{ display: flex; align-items: center; gap: 12px; }}
.logo-box {{
    width: 34px; height: 34px; background: var(--accent); border-radius: 8px;
    display: flex; align-items: center; justify-content: center; font-size: 18px;
    box-shadow: 0 4px 15px var(--accent-bg);
}}
.logo-text {{ font-weight: 800; font-size: 1.2rem; letter-spacing: -0.02em; }}
.logo-text span {{ color: var(--accent); }}

.status-pill {{
    background: var(--surface2); border: 1px solid var(--border);
    padding: 6px 14px; border-radius: 100px; font-family: 'DM Mono', monospace;
    font-size: 0.7rem; color: var(--text2); display: flex; align-items: center; gap: 8px;
}}
.dot {{ width: 8px; height: 8px; border-radius: 50%; }}
.dot-idle {{ background: var(--green); }}
.dot-scan {{ background: var(--orange); animation: pulse 1s infinite; }}

@keyframes pulse {{ 0%{{opacity:1}} 50%{{opacity:0.3}} 100%{{opacity:1}} }}

/* Metric Cards */
.metrics-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2.5rem; }}
.m-card {{
    background: var(--surface); border: 1px solid var(--border);
    padding: 1.5rem; border-radius: 16px; box-shadow: var(--card-shadow);
    transition: transform 0.2s ease;
}}
.m-card:hover {{ transform: translateY(-3px); border-color: var(--accent); }}
.m-label {{ color: var(--muted); font-size: 0.65rem; text-transform: uppercase; font-family: 'DM Mono', monospace; letter-spacing: 0.1em; }}
.m-val {{ font-size: 2.2rem; font-weight: 800; margin-top: 5px; }}

/* Input and Buttons */
[data-testid="stTextInput"] input {{
    background: var(--surface) !important; border: 1px solid var(--border) !important;
    border-radius: 12px !important; color: var(--text) !important;
    font-family: 'DM Mono', monospace !important; padding: 1.2rem !important;
}}
[data-testid="stTextInput"] label {{ display: none !important; }}

[data-testid="stTextInput"] input::placeholder {{
    color: var(--muted) !important;
    opacity: 0.8 !important;
}}

button {{
    border-radius: 12px !important; font-weight: 700 !important;
    text-transform: uppercase !important; letter-spacing: 0.05em !important;
    transition: all 0.2s !important;
}}
button[kind="primary"] {{ background: var(--accent) !important; border: none !important; }}
button[kind="secondary"] {{ background: var(--toggle) !important; border: 1px solid var(--border) !important; }}

/* Custom Rounded Black Toggle Button Styling */
div[data-testid="column"]:nth-child(2) button {{
    background-color: #000000 !important;
    color: #ffffff !important;
    border: 1px solid #333333 !important;
    border-radius: 50% !important;
    width: 45px !important;
    height: 45px !important;
    padding: 0 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    margin-left: auto !important;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
}}

div[data-testid="column"]:nth-child(2) button:hover {{
    border-color: var(--accent) !important;
    transform: scale(1.1) !important;
}}

/* Expanders for Findings */
.stExpander {{
    background: var(--surface) !important; border: 1px solid var(--border) !important;
    border-radius: 12px !important; margin-bottom: 0.5rem !important;
}}
.f-tag {{
    font-family: 'DM Mono', monospace; font-size: 0.6rem; font-weight: 700;
    padding: 2px 8px; border-radius: 4px; margin-right: 10px;
    text-transform: uppercase;
}}
.tag-crit {{ background: rgba(255,77,109,0.15); color: var(--red); }}
.tag-high {{ background: rgba(255,169,77,0.15); color: var(--orange); }}

.detail-row {{ display: grid; grid-template-columns: 100px 1fr; gap: 10px; font-size: 0.8rem; margin: 4px 0; }}
.detail-k {{ color: var(--muted); font-family: 'DM Mono', monospace; }}
.detail-v {{ color: var(--text2); font-family: 'DM Mono', monospace; word-break: break-all; }}

</style>
""", unsafe_allow_html=True)

# ── Top Bar ──────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="top-nav">
    <div class="logo-area">
        <div class="logo-box">🛡️</div>
        <div class="logo-text">Web<span>Sec</span></div>
    </div>
    <div style="display: flex; gap: 1rem; align-items: center;">
        <div class="status-pill">
            <div class="dot {'dot-scan' if st.session_state.status == 'SCANNING' else 'dot-idle'}"></div>
            {st.session_state.status}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Main UI ───────────────────────────────────────────────────────────────────
col_hl, col_tog = st.columns([0.85, 0.15])
with col_hl:
    st.markdown(f"<p style='color: var(--accent); font-family: DM Mono; font-size: 0.7rem; font-weight: 600;'>AUTOMATED SECURITY AUDIT</p>", unsafe_allow_html=True)
    st.markdown("<h1 style='margin-top: -10px; font-weight: 800;'>Website Security Scanner</h1>", unsafe_allow_html=True)
with col_tog:
    # Button stays circular and black via the CSS nth-child selector
    if st.button("☀️" if is_dark else "🌙", type="secondary"):
        st.session_state.theme = "light" if is_dark else "dark"
        st.rerun()

st.markdown("<br>", unsafe_allow_html=True)

# Input area
target_url = st.text_input(
    "Target URL", 
    value=st.session_state.target_url, 
    placeholder="enter URL of target website here"
)

col_q, col_d, _ = st.columns([1, 1, 2])
with col_q:
    quick_btn = st.button("⚡ Quick Scan", type="primary", use_container_width=True)
with col_d:
    deep_btn = st.button("🕷 Deep Scan", type="primary", use_container_width=True)

# ── Scan Execution ────────────────────────────────────────────────────────────
if quick_btn or deep_btn:
    if not target_url.strip():
        st.error("Please provide a valid URL.")
    else:
        st.session_state.target_url = target_url
        st.session_state.status = "SCANNING"
        # Save which button was clicked to session state
        st.session_state.scan_type = "quick" if quick_btn else "deep" 
        st.rerun()

if st.session_state.status == "SCANNING":
    url = st.session_state.target_url
    if not url.startswith("http"):
        url = "https://" + url
    
    with st.status("🔍 Analyzing target architecture...", expanded=True) as status:
        scanner = WebSecurityScanner(url, max_depth=3)
        try:
            f = io.StringIO()
            with redirect_stdout(f):
                # Check the session state variable instead of the button state
                if st.session_state.scan_type == "quick":
                    vulns = scanner.quickscan()
                else:
                    vulns = scanner.deepscan()
            
            st.session_state.vulns = vulns
            st.session_state.urls_cnt = len(scanner.visited_urls)
            st.session_state.scan_done = True
            st.session_state.status = "IDLE"
            status.update(label="Scan complete!", state="complete", expanded=False)
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.error(f"Scan interrupted: {str(e)}")
            st.session_state.status = "IDLE"
            st.rerun()

# ── Dashboard & Results ───────────────────────────────────────────────────────
vulns = st.session_state.vulns
sql_cnt = sum(1 for v in vulns if "SQL" in v.get("type", ""))
xss_cnt = sum(1 for v in vulns if "XSS" in v.get("type", ""))
info_cnt = sum(1 for v in vulns if "Sensitive" in v.get("type", ""))

st.markdown(f"""
<div class="metrics-row">
    <div class="m-card">
        <div class="m-label">Endpoints</div>
        <div class="m-val" style="color: var(--text)">{st.session_state.urls_cnt}</div>
    </div>
    <div class="m-card">
        <div class="m-label">Critical (SQLi)</div>
        <div class="m-val" style="color: var(--red)">{sql_cnt}</div>
    </div>
    <div class="m-card">
        <div class="m-label">High (XSS)</div>
        <div class="m-val" style="color: var(--orange)">{xss_cnt}</div>
    </div>
    <div class="m-card">
        <div class="m-label">Medium</div>
        <div class="m-val" style="color: var(--yellow)">{info_cnt}</div>
    </div>
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
        v_url = v.get("url", "Unknown Source")
        is_crit = "SQL" in v_type
        tag_html = f"<span class='f-tag {'tag-crit' if is_crit else 'tag-high'}'>{'CRITICAL' if is_crit else 'HIGH'}</span>"
        
        with st.expander(f"{v_type} — {v_url[:60]}..."):
            st.markdown(tag_html, unsafe_allow_html=True)
            st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
            for key, val in v.items():
                if key == "type": continue
                is_payload = key in ["payload", "pattern", "parameter"]
                st.markdown(f"""
                <div class="detail-row">
                    <div class="detail-k">{key.upper()}</div>
                    <div class="detail-v" style="color: {'var(--orange)' if is_payload else 'inherit'}">{val}</div>
                </div>
                """, unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div style="margin-top: 4rem; padding: 2rem; border-top: 1px solid var(--border); text-align: center; color: var(--muted); font-family: DM Mono; font-size: 0.65rem;">
    ⚠️ AUTHORIZED USE ONLY &nbsp; • &nbsp; COMPLIANCE REQUIRED &nbsp; • &nbsp; WEBSEC ENGINE V2.5
</div>
""", unsafe_allow_html=True)