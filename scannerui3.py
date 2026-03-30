import streamlit as st
import io
import re
from contextlib import redirect_stdout
from scanner import WebSecurityScanner

st.set_page_config(
    page_title="WebSec Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;500;600;700&display=swap');

:root {
    --bg:          #f0f2f5;
    --surface:     #ffffff;
    --surface2:    #f7f8fa;
    --border:      #dde1e8;
    --border2:     #c8cdd7;
    --accent-blue: #2563eb;
    --accent-purp: #7c3aed;
    --text:        #111827;
    --muted:       #6b7280;
    --red:         #dc2626;
    --orange:      #d97706;
    --yellow:      #ca8a04;
    --green:       #16a34a;
}

html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: 'Inter', sans-serif !important;
}

[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stSidebar"],
#MainMenu, footer { display: none !important; }

[data-testid="stAppViewContainer"] > .main > .block-container {
    padding: 0 !important;
    max-width: 100% !important;
}

/* ── Top bar ── */
.topbar {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    height: 56px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.topbar-left {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-weight: 700;
    font-size: 1.05rem;
    color: var(--text);
}
.topbar-icon {
    width: 22px; height: 22px;
    border: 2px solid var(--accent-blue);
    border-radius: 4px;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.65rem;
    color: var(--accent-blue);
    font-weight: 700;
}
.idle-badge {
    font-size: 0.78rem;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 0.4rem;
}
.idle-badge.idle   { color: var(--green); }
.idle-badge.scan   { color: var(--orange); }
.idle-badge.error  { color: var(--red); }
.status-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    display: inline-block;
    flex-shrink: 0;
}
.dot-idle  { background: var(--green); }
.dot-scan  { background: var(--orange); animation: blink 0.9s infinite; }
.dot-error { background: var(--red); }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.25} }

/* ── Content ── */
.content { padding: 1.75rem 2rem 1rem; }

/* URL input */
[data-testid="stTextInput"] input {
    background: var(--surface) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 6px !important;
    color: var(--text) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.88rem !important;
    padding: 0.7rem 1rem !important;
    height: 46px !important;
    box-shadow: 0 1px 2px rgba(0,0,0,0.05) !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: var(--accent-blue) !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,0.12) !important;
}
[data-testid="stTextInput"] label,
[data-testid="stTextInput"] [data-testid="stWidgetLabel"] { display: none !important; }
[data-testid="stTextInput"] > div { margin-bottom: 0 !important; }

/* Buttons */
div[data-testid="column"]:nth-child(2) [data-testid="stButton"] button,
div[data-testid="column"]:nth-child(3) [data-testid="stButton"] button {
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    height: 46px !important;
    border-radius: 6px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    border: none !important;
    width: 100% !important;
    padding: 0 !important;
}
div[data-testid="column"]:nth-child(2) [data-testid="stButton"] button {
    background: var(--accent-blue) !important;
    color: #fff !important;
}
div[data-testid="column"]:nth-child(3) [data-testid="stButton"] button {
    background: var(--accent-purp) !important;
    color: #fff !important;
}
div[data-testid="column"]:nth-child(2) [data-testid="stButton"] button:hover,
div[data-testid="column"]:nth-child(3) [data-testid="stButton"] button:hover {
    filter: brightness(1.1) !important;
    transform: translateY(-1px) !important;
}

.btn-sub {
    font-size: 0.71rem;
    color: var(--muted);
    text-align: center;
    margin-top: 0.3rem;
    font-family: 'Inter', sans-serif;
}

/* Columns reset */
[data-testid="column"] { padding: 0 !important; }
div[data-testid="stHorizontalBlock"] { gap: 0.75rem !important; }

/* ── Metric cards ── */
.metrics-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
    margin: 1.25rem 0;
}
.metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.1rem 1.4rem 0.9rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    text-align: center;
}
.metric-val {
    font-size: 2.5rem;
    font-weight: 700;
    line-height: 1.1;
    font-family: 'Inter', sans-serif;
}
.mv-blue   { color: var(--accent-blue); }
.mv-red    { color: var(--red); }
.mv-orange { color: var(--orange); }
.mv-yellow { color: var(--yellow); }
.metric-lbl {
    font-size: 0.72rem;
    color: var(--muted);
    font-weight: 500;
    margin-top: 0.3rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}

/* ── Two panels ── */
.panels-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
}
.panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    overflow: hidden;
    display: flex;
    flex-direction: column;
    min-height: 460px;
    max-height: 520px;
}
.panel-hdr {
    padding: 0.65rem 1.1rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    background: var(--surface2);
    flex-shrink: 0;
}
.panel-body {
    flex: 1;
    padding: 0.85rem 1rem;
    overflow-y: auto;
}

/* Log */
.log-out {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #374151;
    line-height: 1.75;
    white-space: pre-wrap;
    word-break: break-all;
}

/* Findings */
.no-findings {
    height: 100%;
    min-height: 300px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--muted);
    font-size: 0.85rem;
}
.f-card {
    border: 1px solid #fecaca;
    border-left: 3px solid var(--red);
    border-radius: 6px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.6rem;
    background: #fff8f8;
    font-size: 0.79rem;
}
.f-card.info {
    border-color: #fde68a;
    border-left-color: var(--yellow);
    background: #fffbf0;
}
.f-title {
    font-weight: 700;
    color: var(--red);
    font-size: 0.82rem;
    margin-bottom: 0.45rem;
}
.f-card.info .f-title { color: var(--yellow); }
.f-row  { display: flex; gap: 0.5rem; margin-top: 0.2rem; flex-wrap: wrap; }
.f-key  { color: var(--muted); font-family: 'JetBrains Mono', monospace; min-width: 75px; flex-shrink: 0; }
.f-val  { color: var(--text);  font-family: 'JetBrains Mono', monospace; word-break: break-all; }
.f-val.pl { color: var(--orange); }

/* Footer */
.footer-bar {
    margin-top: 1.25rem;
    padding: 0.9rem 2rem;
    background: var(--surface);
    border-top: 1px solid var(--border);
    font-size: 0.72rem;
    color: var(--muted);
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────
for k, v in [("status","IDLE"), ("log","Ready. Enter a URL and press Quick Scan or Deep Scan."),
             ("vulns",[]), ("urls_cnt",0)]:
    if k not in st.session_state:
        st.session_state[k] = v

# ── Top bar ───────────────────────────────────────────────────────────────────
s = st.session_state.status
dot_map   = {"IDLE":"dot-idle", "SCANNING":"dot-scan", "ERROR":"dot-error"}
badge_map = {"IDLE":"idle",     "SCANNING":"scan",     "ERROR":"error"}
st.markdown(f"""
<div class='topbar'>
  <div class='topbar-left'>
    <div class='topbar-icon'>W</div>
    WebSec Scanner
  </div>
  <div class='idle-badge {badge_map.get(s,"idle")}'>
    <span class='status-dot {dot_map.get(s,"dot-idle")}'></span>
    {s}
  </div>
</div>
""", unsafe_allow_html=True)

# ── Main content ──────────────────────────────────────────────────────────────
st.markdown("<div class='content'>", unsafe_allow_html=True)

# URL row
col_url, col_q, col_d = st.columns([6, 1.3, 1.3])
with col_url:
    target_url = st.text_input("url", placeholder="https://target.com/page?param=value",
                               label_visibility="collapsed")
with col_q:
    quick_btn = st.button("⚡  Quick Scan", key="quick", use_container_width=True)
    st.markdown("<div class='btn-sub'>Single URL, no crawling</div>", unsafe_allow_html=True)
with col_d:
    deep_btn = st.button("🕷  Deep Scan", key="deep", use_container_width=True)
    st.markdown("<div class='btn-sub'>Crawls entire site</div>", unsafe_allow_html=True)

# ── Trigger scan ─────────────────────────────────────────────────────────────
mode = "quick" if quick_btn else ("deep" if deep_btn else None)

if mode:
    if not target_url.strip():
        st.warning("Please enter a target URL first.")
    else:
        url = target_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        st.session_state.status = "SCANNING"
        buf = io.StringIO()
        scanner = WebSecurityScanner(url, max_depth=3)
        try:
            with redirect_stdout(buf):
                vulns = scanner.quickscan() if mode == "quick" else scanner.deepscan()
            raw = re.sub(r'\x1b\[[0-9;]*m', '', buf.getvalue()).strip()
            st.session_state.log      = raw or "Scan complete. No console output."
            st.session_state.vulns    = vulns
            st.session_state.urls_cnt = len(scanner.visited_urls)
            st.session_state.status   = "IDLE"
        except Exception as e:
            st.session_state.log    = f"ERROR: {e}"
            st.session_state.status = "ERROR"
        st.rerun()

# ── Metrics ───────────────────────────────────────────────────────────────────
vulns    = st.session_state.vulns
sql_cnt  = sum(1 for v in vulns if "SQL"       in v.get("type",""))
xss_cnt  = sum(1 for v in vulns if "XSS"       in v.get("type",""))
info_cnt = sum(1 for v in vulns if "Sensitive" in v.get("type",""))

st.markdown(f"""
<div class='metrics-row'>
  <div class='metric-card'>
    <div class='metric-val mv-blue'>{st.session_state.urls_cnt}</div>
    <div class='metric-lbl'>URLs Scanned</div>
  </div>
  <div class='metric-card'>
    <div class='metric-val mv-red'>{sql_cnt}</div>
    <div class='metric-lbl'>Critical (SQLi)</div>
  </div>
  <div class='metric-card'>
    <div class='metric-val mv-orange'>{xss_cnt}</div>
    <div class='metric-lbl'>High (XSS)</div>
  </div>
  <div class='metric-card'>
    <div class='metric-val mv-yellow'>{info_cnt}</div>
    <div class='metric-lbl'>Medium (Info)</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Build findings HTML ───────────────────────────────────────────────────────
if not vulns:
    findings_html = "<div class='no-findings'>No findings yet.</div>"
else:
    cards = ""
    for v in vulns:
        is_info = "Sensitive" in v.get("type","")
        cls = "f-card info" if is_info else "f-card"
        rows = ""
        for k, val in v.items():
            if k == "type": continue
            extra = "pl" if k in ("payload","pattern") else ""
            rows += f"<div class='f-row'><span class='f-key'>{k}</span><span class='f-val {extra}'>{val}</span></div>"
        cards += f"<div class='{cls}'><div class='f-title'>{v.get('type','Unknown')}</div>{rows}</div>"
    findings_html = cards

# ── Two-panel row ─────────────────────────────────────────────────────────────
log_escaped = st.session_state.log.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

st.markdown(f"""
<div class='panels-row'>
  <div class='panel'>
    <div class='panel-hdr'>Live Output</div>
    <div class='panel-body'><div class='log-out'>{log_escaped}</div></div>
  </div>
  <div class='panel'>
    <div class='panel-hdr'>Findings</div>
    <div class='panel-body'>{findings_html}</div>
  </div>
</div>
""", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class='footer-bar'>
  ⚠ &nbsp; Only scan systems you own or have explicit permission to test.
</div>
""", unsafe_allow_html=True)
