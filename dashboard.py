import streamlit as st
import sys
import io
from contextlib import redirect_stdout
from scanner import WebSecurityScanner

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebSec Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap');

:root {
    --bg:        #0a0c10;
    --surface:   #0f1318;
    --border:    #1e2530;
    --accent:    #00ff9d;
    --accent2:   #ff3c5a;
    --warn:      #ffb700;
    --muted:     #4a5568;
    --text:      #e2e8f0;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Syne', sans-serif;
}

/* Global reset */
html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--sans) !important;
}

[data-testid="stHeader"] { display: none !important; }
[data-testid="stToolbar"] { display: none !important; }
[data-testid="stSidebar"] { display: none !important; }
#MainMenu { display: none !important; }
footer { display: none !important; }

/* Main content padding */
[data-testid="stAppViewContainer"] > .main > .block-container {
    padding: 2rem 3rem 4rem 3rem !important;
    max-width: 1100px !important;
}

/* ── Hero header ── */
.hero {
    display: flex;
    align-items: flex-end;
    gap: 1.5rem;
    margin-bottom: 0.25rem;
}
.hero-badge {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.15em;
    color: var(--accent);
    background: rgba(0,255,157,0.08);
    border: 1px solid rgba(0,255,157,0.25);
    padding: 0.3rem 0.75rem;
    border-radius: 2px;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
    display: inline-block;
}
.hero-title {
    font-family: var(--sans);
    font-size: 3rem;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -0.03em;
    color: #fff;
    margin: 0;
}
.hero-title span { color: var(--accent); }
.hero-sub {
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--muted);
    letter-spacing: 0.05em;
    margin-top: 0.5rem;
    margin-bottom: 2rem;
}

/* Divider */
.divider {
    border: none;
    border-top: 1px solid var(--border);
    margin: 1.5rem 0;
}

/* ── URL input ── */
[data-testid="stTextInput"] input {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 4px !important;
    color: var(--text) !important;
    font-family: var(--mono) !important;
    font-size: 0.9rem !important;
    padding: 0.75rem 1rem !important;
    transition: border-color 0.2s;
}
[data-testid="stTextInput"] input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 2px rgba(0,255,157,0.12) !important;
}
[data-testid="stTextInput"] label {
    font-family: var(--mono) !important;
    font-size: 0.72rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    color: var(--muted) !important;
}

/* ── Mode selector (radio) ── */
[data-testid="stRadio"] label {
    font-family: var(--mono) !important;
    font-size: 0.8rem !important;
    color: var(--text) !important;
}
[data-testid="stRadio"] > div {
    gap: 1.5rem !important;
    flex-direction: row !important;
}
[data-testid="stRadio"] [data-testid="stMarkdownContainer"] p {
    font-family: var(--sans) !important;
    font-size: 0.72rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    color: var(--muted) !important;
    margin-bottom: 0.4rem !important;
}

/* ── Buttons ── */
[data-testid="stButton"] button {
    background: var(--accent) !important;
    color: #000 !important;
    font-family: var(--sans) !important;
    font-weight: 700 !important;
    font-size: 0.85rem !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    border: none !important;
    border-radius: 3px !important;
    padding: 0.65rem 2rem !important;
    transition: opacity 0.15s, transform 0.1s !important;
}
[data-testid="stButton"] button:hover {
    opacity: 0.88 !important;
    transform: translateY(-1px) !important;
}
[data-testid="stButton"] button:active {
    transform: translateY(0) !important;
}

/* ── Progress / status ── */
[data-testid="stSpinner"] {
    font-family: var(--mono) !important;
    color: var(--accent) !important;
}

/* ── Metric cards ── */
.metrics-row {
    display: flex;
    gap: 1rem;
    margin: 1.5rem 0;
}
.metric-card {
    flex: 1;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1.25rem 1.5rem;
    position: relative;
    overflow: hidden;
}
.metric-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
}
.metric-card.danger::before  { background: var(--accent2); }
.metric-card.warning::before { background: var(--warn); }
.metric-label {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.5rem;
}
.metric-value {
    font-family: var(--sans);
    font-size: 2.5rem;
    font-weight: 800;
    line-height: 1;
    color: #fff;
}
.metric-card.danger  .metric-value { color: var(--accent2); }
.metric-card.warning .metric-value { color: var(--warn); }

/* ── Vuln cards ── */
.vuln-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent2);
    border-radius: 4px;
    padding: 1.1rem 1.4rem;
    margin-bottom: 0.75rem;
    font-family: var(--mono);
    font-size: 0.82rem;
}
.vuln-type {
    font-family: var(--sans);
    font-weight: 700;
    font-size: 0.9rem;
    color: var(--accent2);
    margin-bottom: 0.6rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.vuln-type::before {
    content: '◈';
    font-size: 0.7rem;
}
.vuln-row {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.3rem;
    flex-wrap: wrap;
}
.vuln-key {
    color: var(--muted);
    min-width: 90px;
    flex-shrink: 0;
}
.vuln-val {
    color: var(--text);
    word-break: break-all;
}
.vuln-val.payload {
    color: var(--warn);
    background: rgba(255,183,0,0.08);
    padding: 0.1rem 0.4rem;
    border-radius: 2px;
}

/* ── No vulns ── */
.clean-banner {
    background: rgba(0,255,157,0.05);
    border: 1px solid rgba(0,255,157,0.2);
    border-radius: 4px;
    padding: 1.5rem 2rem;
    font-family: var(--mono);
    color: var(--accent);
    font-size: 0.85rem;
    letter-spacing: 0.05em;
    text-align: center;
}

/* ── Log box ── */
.log-box {
    background: #070a0d;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1rem 1.25rem;
    font-family: var(--mono);
    font-size: 0.75rem;
    color: var(--muted);
    max-height: 200px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
}

/* ── Section label ── */
.section-label {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.75rem;
    margin-top: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}
.section-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
}

/* Streamlit columns gap fix */
[data-testid="column"] { padding: 0 0.4rem !important; }
[data-testid="column"]:first-child { padding-left: 0 !important; }
[data-testid="column"]:last-child  { padding-right: 0 !important; }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class='hero-badge'>Security Tooling</div>
<h1 class='hero-title'>Web<span>Sec</span> Scanner</h1>
<p class='hero-sub'>SQLi · XSS · Sensitive Data Exposure — automated surface-level auditing</p>
<hr class='divider'>
""", unsafe_allow_html=True)

# ── Input form ────────────────────────────────────────────────────────────────
col1, col2 = st.columns([3, 1])

with col1:
    target_url = st.text_input(
        "Target URL",
        placeholder="https://example.com/page?id=1",
        label_visibility="visible",
    )

with col2:
    mode = st.radio(
        "Scan Mode",
        options=["Quick Scan", "Deep Scan"],
        help="Quick: target URL only. Deep: crawl + scan all discovered pages.",
    )

depth = 3
if mode == "Deep Scan":
    depth = st.slider("Crawl Depth", min_value=1, max_value=5, value=3)

run = st.button("▶  Run Scan", use_container_width=False)

# ── Scan logic ────────────────────────────────────────────────────────────────
if run:
    if not target_url.strip():
        st.error("Please enter a target URL before scanning.")
    else:
        url = target_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        with st.spinner("Scanning …"):
            log_buffer = io.StringIO()
            scanner = WebSecurityScanner(url, max_depth=depth)

            try:
                with redirect_stdout(log_buffer):
                    if mode == "Quick Scan":
                        vulns = scanner.quickscan()
                    else:
                        vulns = scanner.deepscan()
                scan_ok = True
            except Exception as exc:
                scan_ok = False
                error_msg = str(exc)

        if not scan_ok:
            st.error(f"Scan failed: {error_msg}")
        else:
            urls_scanned = len(scanner.visited_urls)
            vuln_count   = len(vulns)

            # ── Severity bucketing (simple heuristic) ──
            sql_count = sum(1 for v in vulns if "SQL" in v.get("type", ""))
            xss_count = sum(1 for v in vulns if "XSS" in v.get("type", ""))
            info_count = sum(1 for v in vulns if "Sensitive" in v.get("type", ""))

            # Metric cards
            st.markdown(f"""
            <div class='metrics-row'>
                <div class='metric-card'>
                    <div class='metric-label'>URLs Scanned</div>
                    <div class='metric-value'>{urls_scanned}</div>
                </div>
                <div class='metric-card {"danger" if vuln_count else ""}'>
                    <div class='metric-label'>Total Findings</div>
                    <div class='metric-value'>{vuln_count}</div>
                </div>
                <div class='metric-card {"danger" if sql_count else ""}'>
                    <div class='metric-label'>SQL Injection</div>
                    <div class='metric-value'>{sql_count}</div>
                </div>
                <div class='metric-card {"danger" if xss_count else ""}'>
                    <div class='metric-label'>XSS</div>
                    <div class='metric-value'>{xss_count}</div>
                </div>
                <div class='metric-card {"warning" if info_count else ""}'>
                    <div class='metric-label'>Info Exposure</div>
                    <div class='metric-value'>{info_count}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # ── Vulnerability list ──
            st.markdown("<div class='section-label'>Findings</div>", unsafe_allow_html=True)

            if not vulns:
                st.markdown("""
                <div class='clean-banner'>
                    ✓ &nbsp; No vulnerabilities detected on the scanned surface
                </div>
                """, unsafe_allow_html=True)
            else:
                for v in vulns:
                    rows_html = ""
                    for k, val in v.items():
                        if k == "type":
                            continue
                        css_extra = "payload" if k in ("payload", "pattern") else ""
                        rows_html += f"""
                        <div class='vuln-row'>
                            <span class='vuln-key'>{k}</span>
                            <span class='vuln-val {css_extra}'>{val}</span>
                        </div>"""
                    st.markdown(f"""
                    <div class='vuln-card'>
                        <div class='vuln-type'>{v.get("type","Unknown")}</div>
                        {rows_html}
                    </div>
                    """, unsafe_allow_html=True)

            # ── Raw log (collapsed) ──
            log_text = log_buffer.getvalue().strip()
            if log_text:
                with st.expander("Raw scanner output"):
                    # Strip ANSI colour codes
                    import re as _re
                    clean_log = _re.sub(r'\x1b\[[0-9;]*m', '', log_text)
                    st.markdown(f"<div class='log-box'>{clean_log}</div>", unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<hr class='divider' style='margin-top:3rem'>
<p style='font-family:var(--mono);font-size:0.65rem;color:var(--muted);text-align:center;letter-spacing:0.1em;'>
    FOR AUTHORISED TESTING ONLY &nbsp;·&nbsp; DO NOT SCAN TARGETS WITHOUT PERMISSION
</p>
""", unsafe_allow_html=True)
