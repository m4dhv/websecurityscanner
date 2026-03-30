import streamlit as st
import io
import re
from contextlib import redirect_stdout
from scanner import WebSecurityScanner

st.set_page_config(
    page_title="WebSec Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Session State ─────────────────────────────────────────────────────────────
for k, v in [
    ("theme", "dark"),
    ("status", "IDLE"),
    ("vulns", []),
    ("urls_cnt", 0),
    ("scan_done", False),
    ("scanning", False),
]:
    if k not in st.session_state:
        st.session_state[k] = v

is_dark = st.session_state.theme == "dark"

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap');

/* ── Theme variables ── */
[data-theme="dark"] {{
  --bg:           #07090f;
  --bg2:          #0d1017;
  --surface:      #111520;
  --surface2:     #161b2c;
  --border:       #1e2540;
  --border2:      #2a334f;
  --text:         #e8ecf4;
  --text2:        #9ba3be;
  --muted:        #5a6480;
  --accent:       #4f7cff;
  --accent2:      #6e9bff;
  --green:        #22c55e;
  --red:          #ff4d6d;
  --orange:       #ffa94d;
  --yellow:       #ffd43b;
  --btn-quick-bg: #1e3a5f;
  --btn-quick-fg: #60a5fa;
  --btn-quick-border: #2d5a9e;
  --btn-deep-bg:  #2d1b69;
  --btn-deep-fg:  #a78bfa;
  --btn-deep-border: #4c2d9e;
  --card-bg:      #111520;
  --card-shine:   rgba(79,124,255,0.04);
  --toggle-track: #1e2540;
  --toggle-knob:  #4f7cff;
  --toggle-icon-color: #e8ecf4;
  --scan-btn-bg:  linear-gradient(135deg, #4f7cff 0%, #7c4fff 100%);
  --scan-btn-shadow: rgba(79,124,255,0.35);
  --tag-bg:       rgba(79,124,255,0.1);
  --tag-border:   rgba(79,124,255,0.2);
}}
[data-theme="light"] {{
  --bg:           #f0f4ff;
  --bg2:          #e8eeff;
  --surface:      #ffffff;
  --surface2:     #f5f7ff;
  --border:       #dde3f5;
  --border2:      #c5ceee;
  --text:         #0f1629;
  --text2:        #3d4a6e;
  --muted:        #8693b8;
  --accent:       #2952e3;
  --accent2:      #1a3db5;
  --green:        #16a34a;
  --red:          #dc2626;
  --orange:       #d97706;
  --yellow:       #b45309;
  --btn-quick-bg: #dbeafe;
  --btn-quick-fg: #1d4ed8;
  --btn-quick-border: #bfdbfe;
  --btn-deep-bg:  #ede9fe;
  --btn-deep-fg:  #6d28d9;
  --btn-deep-border: #ddd6fe;
  --card-bg:      #ffffff;
  --card-shine:   rgba(41,82,227,0.03);
  --toggle-track: #dde3f5;
  --toggle-knob:  #2952e3;
  --toggle-icon-color: #0f1629;
  --scan-btn-bg:  linear-gradient(135deg, #2952e3 0%, #6d28d9 100%);
  --scan-btn-shadow: rgba(41,82,227,0.3);
  --tag-bg:       rgba(41,82,227,0.08);
  --tag-border:   rgba(41,82,227,0.18);
}}

/* ── Base ── */
html, body,
[data-testid="stAppViewContainer"] {{
  background: var(--bg) !important;
  color: var(--text) !important;
  font-family: 'Syne', sans-serif !important;
  transition: background 0.45s ease, color 0.45s ease;
}}
[data-testid="stHeader"], [data-testid="stToolbar"],
[data-testid="stSidebar"], #MainMenu, footer {{ display:none !important; }}
[data-testid="stAppViewContainer"] > .main > .block-container {{
  padding: 0 !important; max-width: 100% !important;
}}
[data-testid="column"] {{ padding: 0 !important; }}
div[data-testid="stHorizontalBlock"] {{ gap: 0.6rem !important; align-items: center !important; }}
[data-testid="stTextInput"] > div {{ margin-bottom: 0 !important; }}
[data-testid="stTextInput"] label,
[data-testid="stTextInput"] [data-testid="stWidgetLabel"] {{ display:none !important; }}

/* ── Topbar ── */
.topbar {{
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 2.5rem;
  height: 58px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 200;
  backdrop-filter: blur(16px);
  transition: background 0.45s, border-color 0.45s;
}}
.brand {{
  display: flex; align-items: center; gap: 10px;
}}
.brand-logo {{
  width: 30px; height: 30px;
  background: var(--scan-btn-bg);
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 15px;
  box-shadow: 0 4px 12px var(--scan-btn-shadow);
  transition: box-shadow 0.45s;
}}
.brand-text {{
  font-weight: 800; font-size: 1rem;
  letter-spacing: -0.02em; color: var(--text);
  transition: color 0.45s;
}}
.brand-text span {{ color: var(--accent); }}
.brand-ver {{
  font-family: 'DM Mono', monospace;
  font-size: 0.6rem; color: var(--muted);
  background: var(--tag-bg); border: 1px solid var(--tag-border);
  padding: 2px 7px; border-radius: 100px;
  transition: background 0.45s, border-color 0.45s;
}}
.topbar-right {{
  display: flex; align-items: center; gap: 1.2rem;
}}
.status-pill {{
  display: flex; align-items: center; gap: 6px;
  font-family: 'DM Mono', monospace; font-size: 0.68rem;
  color: var(--muted);
  background: var(--surface2); border: 1px solid var(--border);
  padding: 5px 12px; border-radius: 100px;
  transition: all 0.45s;
}}
.sdot {{
  width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0;
  transition: background 0.3s;
}}
.sdot-idle     {{ background: var(--green); }}
.sdot-scanning {{ background: var(--orange); animation: sdotpulse 0.7s infinite; }}
.sdot-error    {{ background: var(--red); }}
@keyframes sdotpulse {{ 0%,100%{{opacity:1;transform:scale(1)}} 50%{{opacity:0.3;transform:scale(0.7)}} }}

/* ── Yalamps-style toggle ── */
.theme-toggle {{
  position: relative;
  width: 64px; height: 32px;
  cursor: pointer;
  user-select: none;
}}
.toggle-track {{
  width: 64px; height: 32px;
  background: var(--toggle-track);
  border-radius: 100px;
  border: 1px solid var(--border2);
  transition: background 0.4s, border-color 0.4s;
  position: relative; overflow: hidden;
}}
.toggle-icons {{
  position: absolute; top: 0; left: 0; right: 0; bottom: 0;
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 7px;
  font-size: 13px; pointer-events: none;
  z-index: 1;
}}
.toggle-knob {{
  position: absolute;
  top: 3px;
  width: 24px; height: 24px;
  background: var(--toggle-knob);
  border-radius: 50%;
  transition: left 0.4s cubic-bezier(.68,-.55,.27,1.55), background 0.4s;
  box-shadow: 0 2px 8px rgba(0,0,0,0.25);
  z-index: 2;
  {"left: 3px;" if is_dark else "left: 35px;"}
}}

/* ── Page body ── */
.page {{
  padding: 2.5rem 2.5rem 2rem;
  max-width: 960px; margin: 0 auto;
}}

/* ── Headline ── */
.headline {{
  margin-bottom: 2rem;
}}
.hl-badge {{
  display: inline-flex; align-items: center; gap: 6px;
  font-family: 'DM Mono', monospace; font-size: 0.65rem; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.12em;
  color: var(--accent); background: var(--tag-bg);
  border: 1px solid var(--tag-border);
  padding: 4px 12px; border-radius: 100px;
  margin-bottom: 0.9rem;
  transition: all 0.45s;
}}
.hl-title {{
  font-size: 2.4rem; font-weight: 800;
  letter-spacing: -0.03em; line-height: 1.1;
  color: var(--text); margin: 0 0 0.5rem;
  transition: color 0.45s;
}}
.hl-title span {{ color: var(--accent); }}
.hl-sub {{
  font-family: 'DM Mono', monospace;
  font-size: 0.78rem; color: var(--text2);
  transition: color 0.45s;
}}

/* ── URL input ── */
[data-testid="stTextInput"] input {{
  background: var(--surface) !important;
  border: 1.5px solid var(--border2) !important;
  border-radius: 10px !important;
  color: var(--text) !important;
  font-family: 'DM Mono', monospace !important;
  font-size: 0.88rem !important;
  padding: 0.8rem 1.1rem !important;
  height: 48px !important;
  transition: border-color 0.2s, box-shadow 0.2s, background 0.45s !important;
}}
[data-testid="stTextInput"] input::placeholder {{
  color: var(--muted) !important; opacity: 1 !important;
}}
[data-testid="stTextInput"] input:focus {{
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 3px var(--tag-bg) !important;
}}

/* ── Scan buttons (col 2 = quick, col 3 = deep) ── */
div[data-testid="column"]:nth-child(2) [data-testid="stButton"] button,
div[data-testid="column"]:nth-child(3) [data-testid="stButton"] button {{
  display: flex !important; align-items: center !important;
  justify-content: center !important; gap: 6px !important;
  height: 48px !important; border-radius: 10px !important;
  font-family: 'Syne', sans-serif !important; font-weight: 700 !important;
  font-size: 0.82rem !important; width: 100% !important;
  letter-spacing: 0.02em !important;
  transition: transform 0.15s, filter 0.15s !important;
  border: 1.5px solid transparent !important;
}}
div[data-testid="column"]:nth-child(2) [data-testid="stButton"] button {{
  background: var(--btn-quick-bg) !important;
  color: var(--btn-quick-fg) !important;
  border-color: var(--btn-quick-border) !important;
}}
div[data-testid="column"]:nth-child(3) [data-testid="stButton"] button {{
  background: var(--btn-deep-bg) !important;
  color: var(--btn-deep-fg) !important;
  border-color: var(--btn-deep-border) !important;
}}
div[data-testid="column"]:nth-child(2) [data-testid="stButton"] button:hover,
div[data-testid="column"]:nth-child(3) [data-testid="stButton"] button:hover {{
  filter: brightness(1.15) !important;
  transform: translateY(-2px) !important;
}}
.btn-sub {{
  font-family: 'DM Mono', monospace;
  font-size: 0.62rem; color: var(--muted);
  text-align: center; margin-top: 5px;
  transition: color 0.45s;
}}

/* ── Hidden theme-trigger button ── */
div[data-testid="column"]:nth-child(4) [data-testid="stButton"] button {{
  opacity: 0 !important; position: absolute !important;
  width: 64px !important; height: 32px !important;
  cursor: pointer !important; z-index: 10 !important;
  border: none !important; background: transparent !important;
  padding: 0 !important; margin: 0 !important;
}}

/* ── Metrics ── */
.metrics {{
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 0.75rem; margin: 2rem 0;
}}
.mc {{
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 12px; padding: 1.3rem 1.4rem 1.1rem;
  position: relative; overflow: hidden;
  transition: background 0.45s, border-color 0.45s, transform 0.2s;
}}
.mc::before {{
  content: '';
  position: absolute; top:0; left:0; right:0; bottom:0;
  background: var(--card-shine); pointer-events: none;
}}
.mc:hover {{ transform: translateY(-2px); }}
.mc-bar {{
  position: absolute; top:0; left:0; right:0; height:2px; border-radius:12px 12px 0 0;
}}
.mc-label {{
  font-family: 'DM Mono', monospace; font-size: 0.62rem; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--muted); margin-bottom: 0.55rem;
  transition: color 0.45s;
}}
.mc-val {{
  font-family: 'Syne', sans-serif; font-size: 2.3rem; font-weight: 800;
  line-height: 1; transition: color 0.45s;
}}
.mc-hint {{
  font-family: 'DM Mono', monospace; font-size: 0.62rem;
  color: var(--muted); margin-top: 0.4rem;
  transition: color 0.45s;
}}

/* ── Findings panel ── */
.findings-panel {{
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 14px; overflow: hidden;
  transition: background 0.45s, border-color 0.45s;
}}
.fp-hdr {{
  display: flex; align-items: center; justify-content: space-between;
  padding: 0.8rem 1.3rem;
  background: var(--surface2); border-bottom: 1px solid var(--border);
  transition: background 0.45s, border-color 0.45s;
}}
.fp-title {{
  font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.1em; color: var(--text2);
  transition: color 0.45s;
}}
.fp-badge {{
  font-family: 'DM Mono', monospace; font-size: 0.62rem;
  color: var(--muted); background: var(--tag-bg);
  border: 1px solid var(--tag-border);
  padding: 2px 9px; border-radius: 100px;
  transition: all 0.45s;
}}
.fp-body {{
  padding: 1.1rem; max-height: 460px; overflow-y: auto;
}}
.fp-body::-webkit-scrollbar {{ width: 4px; }}
.fp-body::-webkit-scrollbar-track {{ background: transparent; }}
.fp-body::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 4px; }}

/* ── Finding cards ── */
.f-card {{
  border: 1px solid var(--border);
  border-radius: 10px; overflow: hidden;
  margin-bottom: 0.65rem;
  transition: border-color 0.2s, transform 0.15s, background 0.45s;
}}
.f-card:hover {{ border-color: var(--border2); transform: translateX(3px); }}
.f-hdr {{
  display: flex; align-items: center; gap: 8px;
  padding: 0.6rem 0.9rem;
  background: var(--surface2);
  border-bottom: 1px solid var(--border);
  transition: background 0.45s, border-color 0.45s;
}}
.sev-pill {{
  font-family: 'DM Mono', monospace;
  font-size: 0.58rem; font-weight: 500; text-transform: uppercase;
  letter-spacing: 0.08em; padding: 2px 8px; border-radius: 100px;
}}
.sev-crit {{ background:rgba(255,77,109,0.15); color:var(--red);    border:1px solid rgba(255,77,109,0.25); }}
.sev-high {{ background:rgba(255,169,77,0.15); color:var(--orange); border:1px solid rgba(255,169,77,0.25); }}
.sev-med  {{ background:rgba(79,124,255,0.12); color:var(--accent); border:1px solid rgba(79,124,255,0.22); }}
.f-type {{ font-size: 0.8rem; font-weight: 700; color: var(--text); transition: color 0.45s; }}
.f-body {{ padding: 0.7rem 0.9rem; display:flex; flex-direction:column; gap:0.3rem; }}
.f-row  {{ display:flex; gap:0.6rem; font-size:0.75rem; align-items:flex-start; }}
.f-key  {{ font-family:'DM Mono',monospace; color:var(--muted); min-width:70px; flex-shrink:0; transition:color 0.45s; }}
.f-val  {{ font-family:'DM Mono',monospace; color:var(--text2); word-break:break-all; line-height:1.5; transition:color 0.45s; }}
.f-val.p {{ color:var(--orange); background:rgba(255,169,77,0.08); padding:1px 6px; border-radius:4px; }}

/* ── Empty / clean states ── */
.empty-state {{
  display:flex; flex-direction:column; align-items:center;
  justify-content:center; min-height:220px; gap:0.6rem;
  color:var(--muted); text-align:center; padding:2rem;
}}
.empty-icon {{ font-size:2rem; opacity:0.35; }}
.empty-txt  {{ font-family:'DM Mono',monospace; font-size:0.78rem; }}
.clean-state {{
  display:flex; align-items:center; justify-content:center;
  gap:0.7rem; min-height:220px;
  color:var(--green); font-family:'DM Mono',monospace; font-size:0.82rem;
}}

/* ── Scan animation overlay ── */
.scan-overlay {{
  display:none; /* shown via JS */
  position:fixed; inset:0; z-index:500;
  background: {"rgba(7,9,15,0.92)" if is_dark else "rgba(240,244,255,0.92)"};
  backdrop-filter: blur(10px);
  flex-direction:column; align-items:center; justify-content:center;
  gap:1.8rem;
}}
.scan-overlay.active {{ display:flex; }}

/* Radar rings */
.radar {{
  position:relative; width:120px; height:120px;
  display:flex; align-items:center; justify-content:center;
}}
.radar-ring {{
  position:absolute; border-radius:50%;
  border: 1.5px solid var(--accent);
  opacity:0;
  animation: radarExpand 2.4s ease-out infinite;
}}
.radar-ring:nth-child(1) {{ width:40px;  height:40px;  animation-delay:0s; }}
.radar-ring:nth-child(2) {{ width:72px;  height:72px;  animation-delay:0.6s; }}
.radar-ring:nth-child(3) {{ width:104px; height:104px; animation-delay:1.2s; }}
.radar-ring:nth-child(4) {{ width:136px; height:136px; animation-delay:1.8s; }}
@keyframes radarExpand {{
  0%   {{ opacity:0.9; transform:scale(0.3); }}
  80%  {{ opacity:0.1; transform:scale(1); }}
  100% {{ opacity:0;   transform:scale(1.1); }}
}}
.radar-core {{
  width:22px; height:22px; border-radius:50%;
  background: var(--scan-btn-bg);
  box-shadow: 0 0 20px var(--scan-btn-shadow);
  animation: corePulse 1.2s ease-in-out infinite;
  z-index:1;
}}
@keyframes corePulse {{
  0%,100% {{ transform:scale(1);   box-shadow:0 0 20px var(--scan-btn-shadow); }}
  50%     {{ transform:scale(1.2); box-shadow:0 0 35px var(--scan-btn-shadow); }}
}}

/* Scan sweep line */
.sweep-wrap {{
  position:absolute; width:120px; height:120px;
  animation: rotateSweep 2s linear infinite;
}}
.sweep-line {{
  position:absolute; top:50%; left:50%;
  width:50%; height:1px; transform-origin: left center;
  background: linear-gradient(90deg, var(--accent) 0%, transparent 100%);
  opacity:0.6;
}}
@keyframes rotateSweep {{ from{{transform:rotate(0deg)}} to{{transform:rotate(360deg)}} }}

/* Scanning text */
.scan-label {{
  font-family:'DM Mono',monospace; font-size:0.82rem;
  color: var(--text2); letter-spacing:0.12em; text-transform:uppercase;
}}
.scan-dots::after {{
  content:'';
  animation: dots 1.5s steps(4,end) infinite;
}}
@keyframes dots {{
  0%  {{ content:''; }}
  25% {{ content:'.'; }}
  50% {{ content:'..'; }}
  75% {{ content:'...'; }}
}}

/* Scanning bar */
.scan-bar-wrap {{
  width:200px; height:3px;
  background:var(--border); border-radius:100px; overflow:hidden;
}}
.scan-bar-fill {{
  height:100%; width:40%;
  background:var(--scan-btn-bg);
  border-radius:100px;
  animation: scanSlide 1.6s ease-in-out infinite;
}}
@keyframes scanSlide {{
  0%   {{ transform:translateX(-100%); }}
  100% {{ transform:translateX(350%); }}
}}

/* ── Footer ── */
.footer {{
  border-top:1px solid var(--border); margin-top:2.5rem;
  padding:1.1rem 2.5rem; text-align:center;
  font-family:'DM Mono',monospace; font-size:0.62rem;
  color:var(--muted); letter-spacing:0.06em;
  background:var(--surface);
  transition: all 0.45s;
}}
</style>

<script>
/* Inject theme attr on <html> immediately */
(function() {{
  document.documentElement.setAttribute('data-theme', '{st.session_state.theme}');
}})();
</script>
""", unsafe_allow_html=True)

# Apply theme attr via a persistent script tag
st.markdown(f"""
<script>
document.documentElement.setAttribute('data-theme', '{st.session_state.theme}');
</script>
""", unsafe_allow_html=True)

# ── Topbar ────────────────────────────────────────────────────────────────────
s = st.session_state.status
sdot = {"IDLE":"sdot-idle","SCANNING":"sdot-scanning","ERROR":"sdot-error"}.get(s,"sdot-idle")

knob_pos = "left: 3px;" if is_dark else "left: 35px;"
sun_op   = "opacity:0.35" if is_dark  else "opacity:1"
moon_op  = "opacity:1"    if is_dark  else "opacity:0.35"

st.markdown(f"""
<div class='topbar' id='topbar'>
  <div class='brand'>
    <div class='brand-logo'>🛡️</div>
    <span class='brand-text'>Web<span>Sec</span></span>
    <span class='brand-ver'>v2.1</span>
  </div>
  <div class='topbar-right'>
    <div class='status-pill'>
      <span class='sdot {sdot}'></span>
      {s}
    </div>
    <!-- yalamps-style toggle (visual only, overlaid by hidden Streamlit button) -->
    <div style='position:relative; width:64px; height:32px;'>
      <div class='toggle-track'>
        <div class='toggle-icons'>
          <span style='{sun_op}'>☀️</span>
          <span style='{moon_op}'>🌙</span>
        </div>
        <div class='toggle-knob' style='{knob_pos}'></div>
      </div>
      <!-- invisible streamlit button sits on top -->
      <div id='toggle-btn-wrap' style='position:absolute;inset:0;z-index:10;'></div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Page body ─────────────────────────────────────────────────────────────────
st.markdown("<div class='page'>", unsafe_allow_html=True)

# Headline
st.markdown("""
<div class='headline'>
  <div class='hl-badge'>⬡ Security Tooling</div>
  <h1 class='hl-title'>Web<span>Sec</span> Scanner</h1>
  <p class='hl-sub'>SQLi · XSS · Sensitive Data Exposure — automated surface-level auditing</p>
</div>
""", unsafe_allow_html=True)

# ── Scan controls row ─────────────────────────────────────────────────────────
col_url, col_q, col_d, col_tog = st.columns([5.4, 1.35, 1.35, 0.9])

with col_url:
    target_url = st.text_input("url", placeholder="https://target.com/page?param=value",
                               label_visibility="collapsed")
with col_q:
    quick_btn = st.button("⚡ Quick", key="quick", use_container_width=True)
    st.markdown("<div class='btn-sub'>Single URL</div>", unsafe_allow_html=True)
with col_d:
    deep_btn = st.button("🕷 Deep", key="deep", use_container_width=True)
    st.markdown("<div class='btn-sub'>Crawl site</div>", unsafe_allow_html=True)
with col_tog:
    toggle_btn = st.button("toggle", key="toggle", use_container_width=True)

# Move toggle button under the visual knob via JS
st.markdown("""
<script>
(function move() {
  const wrap = document.getElementById('toggle-btn-wrap');
  const btn  = document.querySelector('[data-testid="column"]:nth-child(4) button');
  if (wrap && btn) { wrap.appendChild(btn); }
  else { setTimeout(move, 80); }
})();
</script>
""", unsafe_allow_html=True)

# ── Scan overlay (shown while scanning) ───────────────────────────────────────
scanning_active = st.session_state.status == "SCANNING"
overlay_cls = "scan-overlay active" if scanning_active else "scan-overlay"
st.markdown(f"""
<div class='{overlay_cls}' id='scan-overlay'>
  <div class='radar'>
    <div class='radar-ring'></div>
    <div class='radar-ring'></div>
    <div class='radar-ring'></div>
    <div class='radar-ring'></div>
    <div class='sweep-wrap'><div class='sweep-line'></div></div>
    <div class='radar-core'></div>
  </div>
  <div class='scan-label'>Scanning<span class='scan-dots'></span></div>
  <div class='scan-bar-wrap'><div class='scan-bar-fill'></div></div>
</div>
""", unsafe_allow_html=True)

# ── Theme toggle logic ────────────────────────────────────────────────────────
if toggle_btn:
    st.session_state.theme = "light" if is_dark else "dark"
    st.rerun()

# ── Scan logic ────────────────────────────────────────────────────────────────
mode = "quick" if quick_btn else ("deep" if deep_btn else None)

if mode:
    if not target_url.strip():
        st.warning("Enter a target URL first.")
    else:
        url = target_url.strip()
        if not url.startswith(("http://","https://")):
            url = "https://" + url
        st.session_state.status = "SCANNING"
        st.rerun()

# Run actual scan after rerun with SCANNING state
if st.session_state.status == "SCANNING" and mode:
    url = target_url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    buf = io.StringIO()
    scanner = WebSecurityScanner(url, max_depth=3)
    try:
        with redirect_stdout(buf):
            vulns = scanner.quickscan() if mode == "quick" else scanner.deepscan()
        st.session_state.vulns     = vulns
        st.session_state.urls_cnt  = len(scanner.visited_urls)
        st.session_state.scan_done = True
    except Exception as e:
        st.session_state.vulns = []
        st.session_state.scan_done = True
    st.session_state.status = "IDLE"
    st.rerun()

# ── Metrics ───────────────────────────────────────────────────────────────────
vulns    = st.session_state.vulns
sql_cnt  = sum(1 for v in vulns if "SQL"       in v.get("type",""))
xss_cnt  = sum(1 for v in vulns if "XSS"       in v.get("type",""))
info_cnt = sum(1 for v in vulns if "Sensitive" in v.get("type",""))

st.markdown(f"""
<div class='metrics'>
  <div class='mc'>
    <div class='mc-bar' style='background:var(--accent)'></div>
    <div class='mc-label'>URLs Scanned</div>
    <div class='mc-val' style='color:var(--accent)'>{st.session_state.urls_cnt}</div>
    <div class='mc-hint'>endpoints checked</div>
  </div>
  <div class='mc'>
    <div class='mc-bar' style='background:var(--red)'></div>
    <div class='mc-label'>Critical — SQLi</div>
    <div class='mc-val' style='color:var(--red)'>{sql_cnt}</div>
    <div class='mc-hint'>injection vectors</div>
  </div>
  <div class='mc'>
    <div class='mc-bar' style='background:var(--orange)'></div>
    <div class='mc-label'>High — XSS</div>
    <div class='mc-val' style='color:var(--orange)'>{xss_cnt}</div>
    <div class='mc-hint'>script injection</div>
  </div>
  <div class='mc'>
    <div class='mc-bar' style='background:var(--muted)'></div>
    <div class='mc-label'>Medium — Info</div>
    <div class='mc-val' style='color:var(--muted)'>{info_cnt}</div>
    <div class='mc-hint'>data exposure</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Findings ──────────────────────────────────────────────────────────────────
if not st.session_state.scan_done:
    body = "<div class='empty-state'><div class='empty-icon'>🔍</div><div class='empty-txt'>Run a scan to see findings here.</div></div>"
    badge = "—"
elif not vulns:
    body = "<div class='clean-state'>✓ &nbsp; No vulnerabilities detected</div>"
    badge = "clean"
else:
    cards = ""
    for v in vulns:
        vt = v.get("type","Unknown")
        if "SQL" in vt:   sc, sl = "sev-crit","Critical"
        elif "XSS" in vt: sc, sl = "sev-high","High"
        else:             sc, sl = "sev-med","Medium"
        rows = ""
        for k, val in v.items():
            if k == "type": continue
            extra = "p" if k in ("payload","pattern") else ""
            ve = str(val).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            rows += f"<div class='f-row'><span class='f-key'>{k}</span><span class='f-val {extra}'>{ve}</span></div>"
        cards += f"""<div class='f-card'>
  <div class='f-hdr'><span class='sev-pill {sc}'>{sl}</span><span class='f-type'>{vt}</span></div>
  <div class='f-body'>{rows}</div>
</div>"""
    body  = cards
    badge = f"{len(vulns)} found"

st.markdown(f"""
<div class='findings-panel'>
  <div class='fp-hdr'>
    <span class='fp-title'>Security Findings</span>
    <span class='fp-badge'>{badge}</span>
  </div>
  <div class='fp-body'>{body}</div>
</div>
""", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)  # .page

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class='footer'>
  ⚠ &nbsp; For authorised security testing only
  &nbsp;·&nbsp; Do not scan targets without explicit permission
</div>
""", unsafe_allow_html=True)

# ── Final theme injection (runs after full render) ────────────────────────────
st.markdown(f"""
<script>
  document.documentElement.setAttribute('data-theme', '{st.session_state.theme}');
</script>
""", unsafe_allow_html=True)
