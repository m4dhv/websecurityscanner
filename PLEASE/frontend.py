import reflex as rx
import requests
import asyncio
from typing import List, Dict
import re

# API Configuration
API_BASE_URL = "http://localhost:8000"
API_KEY = ""  # Will be loaded from config or set by user

class ScanState(rx.State):
    """State management for the scanner frontend"""
    
    # UI State
    target_url: str = ""
    scan_type: str = ""
    status: str = "IDLE"
    theme: str = "dark"
    
    # Scan Results
    vulnerabilities: List[Dict] = []
    urls_scanned: int = 0
    scan_done: bool = False
    scan_id: int = 0
    
    # Real-time Animation
    scan_progress: str = ""
    scan_messages: List[str] = []
    
    # API Key
    api_key: str = ""
    api_key_valid: bool = False
    
    # Computed Properties
    @rx.var
    def sql_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if "SQL" in v.get("type", ""))
    
    @rx.var
    def xss_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if "XSS" in v.get("type", ""))
    
    @rx.var
    def info_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if "Sensitive" in v.get("type", ""))
    
    @rx.var
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities)
    
    @rx.var
    def is_dark(self) -> bool:
        return self.theme == "dark"
    
    def toggle_theme(self):
        """Toggle between dark and light theme"""
        self.theme = "light" if self.theme == "dark" else "dark"
    
    def set_api_key(self, key: str):
        """Set and validate API key"""
        self.api_key = key.strip()
        global API_KEY
        API_KEY = self.api_key
        self.api_key_valid = len(self.api_key) > 0
    
    def validate_url(self, url: str) -> bool:
        """Validate URL format"""
        url_pattern = re.compile(
            r"^(https?://)?(localhost|([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(:\d{1,5})?(/[^\s]*)?$",
            re.IGNORECASE
        )
        return bool(url_pattern.match(url.strip()))
    
    async def start_quickscan(self):
        """Start quick scan"""
        await self.start_scan("quickscan")
    
    async def start_deepscan(self):
        """Start deep scan"""
        await self.start_scan("deepscan")
    
    async def start_scan(self, scan_type: str):
        """Execute scan with real-time updates"""
        clean_url = self.target_url.strip()
        
        # Validation
        if not clean_url:
            self.scan_progress = "❌ Target URL cannot be empty"
            return
        
        if not self.validate_url(clean_url):
            self.scan_progress = f"❌ '{clean_url}' is not a valid URL"
            return
        
        if not self.api_key_valid:
            self.scan_progress = "❌ Please enter a valid API key"
            return
        
        # Ensure URL has scheme
        if not clean_url.startswith(('http://', 'https://')):
            clean_url = 'http://' + clean_url
        
        # Reset state
        self.status = "SCANNING"
        self.scan_type = scan_type
        self.scan_done = False
        self.vulnerabilities = []
        self.scan_messages = []
        self.scan_progress = "🔍 Initializing scanner..."
        
        # Animation messages
        messages = [
            "🔍 Analyzing target architecture...",
            "🌐 Mapping web endpoints...",
            "🔬 Testing for SQL injection...",
            "🛡️ Checking XSS vulnerabilities...",
            "📊 Scanning for sensitive data...",
            "⚡ Finalizing security report..."
        ]
        
        # Show progress messages
        for msg in messages:
            self.scan_messages.append(msg)
            self.scan_progress = msg
            await asyncio.sleep(0.5)
            yield
        
        try:
            # Make API request
            headers = {"Authorization": f"Bearer {self.api_key}"}
            endpoint = f"{API_BASE_URL}/api/{scan_type}"
            payload = {"target_url": clean_url, "max_depth": 3}
            
            self.scan_progress = "📡 Sending request to scanner API..."
            yield
            
            response = requests.post(endpoint, json=payload, headers=headers, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                self.vulnerabilities = data.get("vulnerabilities", [])
                self.urls_scanned = data.get("urls_scanned", 0)
                self.scan_id = data.get("scan_id", 0)
                self.scan_done = True
                self.status = "IDLE"
                self.scan_progress = f"✅ Scan complete! Found {len(self.vulnerabilities)} vulnerabilities"
            elif response.status_code == 401:
                self.scan_progress = "❌ Invalid API key"
                self.status = "IDLE"
            else:
                self.scan_progress = f"❌ Scan failed: {response.text}"
                self.status = "IDLE"
                
        except requests.exceptions.Timeout:
            self.scan_progress = "⏱️ Scan timeout - target may be unreachable"
            self.status = "IDLE"
        except requests.exceptions.ConnectionError:
            self.scan_progress = "❌ Cannot connect to scanner API (is it running?)"
            self.status = "IDLE"
        except Exception as e:
            self.scan_progress = f"❌ Critical error: {str(e)}"
            self.status = "IDLE"

def navbar() -> rx.Component:
    """Top navigation bar"""
    return rx.hstack(
        # Logo area
        rx.hstack(
            rx.box(
                "🛡️",
                class_name="logo-box",
            ),
            rx.text(
                "WebSec",
                rx.text(" Scanner", color="var(--accent)"),
                class_name="logo-text",
            ),
            spacing="3",
        ),
        # Status pill
        rx.hstack(
            rx.box(
                class_name=f"dot dot-{ScanState.status.lower()}",
            ),
            rx.text(ScanState.status, font_family="DM Mono"),
            class_name="status-pill",
        ),
        # Theme toggle
        rx.button(
            rx.cond(
                ScanState.is_dark,
                "☀️",
                "🌙"
            ),
            on_click=ScanState.toggle_theme,
            variant="ghost",
            size="3",
        ),
        justify="between",
        align="center",
        class_name="top-nav",
        width="100%",
    )

def metrics_row() -> rx.Component:
    """Metrics cards showing scan statistics"""
    return rx.hstack(
        rx.vstack(
            rx.text("Endpoints", class_name="m-label"),
            rx.text(ScanState.urls_scanned, class_name="m-val"),
            class_name="m-card",
        ),
        rx.vstack(
            rx.text("Critical (SQLi)", class_name="m-label"),
            rx.text(ScanState.sql_count, class_name="m-val", color="var(--red)"),
            class_name="m-card",
        ),
        rx.vstack(
            rx.text("High (XSS)", class_name="m-label"),
            rx.text(ScanState.xss_count, class_name="m-val", color="var(--orange)"),
            class_name="m-card",
        ),
        rx.vstack(
            rx.text("Medium (Info Leak)", class_name="m-label"),
            rx.text(ScanState.info_count, class_name="m-val", color="var(--yellow)"),
            class_name="m-card",
        ),
        class_name="metrics-row",
        width="100%",
    )

def vulnerability_card(vuln: Dict) -> rx.Component:
    """Individual vulnerability display card"""
    v_type = vuln.get("type", "Unknown Issue")
    v_url = vuln.get("url", "Unknown Source")
    
    # Determine severity
    if "SQL" in v_type:
        sev_class, sev_text = "tag-crit", "CRITICAL"
    elif "XSS" in v_type:
        sev_class, sev_text = "tag-high", "HIGH"
    else:
        sev_class, sev_text = "tag-med", "MEDIUM"
    
    details = []
    for key, val in vuln.items():
        if key != "type":
            details.append(
                rx.hstack(
                    rx.text(key.upper(), class_name="detail-k"),
                    rx.text(
                        str(val),
                        class_name="detail-v",
                        color="var(--orange)" if key in ["payload", "pattern", "parameter"] else "inherit"
                    ),
                    class_name="detail-row",
                    width="100%",
                )
            )
    
    return rx.accordion.root(
        rx.accordion.item(
            header=rx.hstack(
                rx.text(v_type, font_weight="bold"),
                rx.text(" — ", color="var(--muted)"),
                rx.text(v_url[:60] + ("..." if len(v_url) > 60 else "")),
                spacing="1",
            ),
            content=rx.vstack(
                rx.badge(sev_text, color_scheme="red" if sev_class == "tag-crit" else "orange" if sev_class == "tag-high" else "yellow"),
                rx.divider(),
                *details,
                spacing="2",
                width="100%",
            ),
            value=str(hash(v_url)),
        ),
        collapsible=True,
        variant="ghost",
        width="100%",
    )

def scan_animation() -> rx.Component:
    """Real-time scan animation display"""
    return rx.cond(
        ScanState.status == "SCANNING",
        rx.vstack(
            rx.text("🔄 Scanning in progress...", size="5", weight="bold"),
            rx.foreach(
                ScanState.scan_messages,
                lambda msg: rx.text(msg, color="var(--text2)", font_family="DM Mono"),
            ),
            rx.spinner(size="3"),
            rx.text(ScanState.scan_progress, color="var(--accent)", weight="bold"),
            spacing="3",
            padding="2rem",
            border_radius="12px",
            border="1px solid var(--border)",
            background="var(--surface)",
            width="100%",
        ),
        rx.fragment()
    )

def api_key_input() -> rx.Component:
    """API key configuration"""
    return rx.hstack(
        rx.input(
            placeholder="Enter your API key",
            value=ScanState.api_key,
            on_change=ScanState.set_api_key,
            type="password",
            width="100%",
        ),
        rx.cond(
            ScanState.api_key_valid,
            rx.badge("✓ Valid", color_scheme="green"),
            rx.badge("⚠ Required", color_scheme="red"),
        ),
        spacing="2",
        width="100%",
        margin_bottom="1rem",
    )

def index() -> rx.Component:
    """Main scanner interface"""
    return rx.container(
        navbar(),
        
        rx.divider(margin_y="2rem"),
        
        # API Key Input
        api_key_input(),
        
        # Target URL Input
        rx.input(
            placeholder="enter URL of target website here",
            value=ScanState.target_url,
            on_change=ScanState.set_target_url,
            size="3",
            width="100%",
            margin_bottom="1rem",
        ),
        
        # Scan Buttons
        rx.hstack(
            rx.button(
                "⚡ Quick Scan",
                on_click=ScanState.start_quickscan,
                size="3",
                color_scheme="green",
                disabled=ScanState.status == "SCANNING",
            ),
            rx.button(
                "🕷 Deep Scan",
                on_click=ScanState.start_deepscan,
                size="3",
                color_scheme="green",
                disabled=ScanState.status == "SCANNING",
            ),
            spacing="3",
            justify="center",
            width="100%",
            margin_bottom="2rem",
        ),
        
        # Scan Animation
        scan_animation(),
        
        # Metrics
        metrics_row(),
        
        # Results Section
        rx.heading("Security Findings", size="6", margin_top="2rem", margin_bottom="1rem"),
        
        rx.cond(
            ~ScanState.scan_done,
            rx.callout.root(
                rx.callout.icon(rx.icon("info")),
                rx.callout.text("No active scan results. Enter a target URL and choose a scan mode to begin."),
                color_scheme="blue",
            ),
            rx.cond(
                ScanState.total_vulnerabilities == 0,
                rx.callout.root(
                    rx.callout.icon(rx.icon("check")),
                    rx.callout.text("Target surface appears clean. No vulnerabilities detected."),
                    color_scheme="green",
                ),
                rx.vstack(
                    rx.foreach(
                        ScanState.vulnerabilities,
                        vulnerability_card,
                    ),
                    spacing="2",
                    width="100%",
                )
            )
        ),
        
        # Footer
        rx.divider(margin_top="4rem"),
        rx.text(
            "⚠️ AUTHORIZED USE ONLY • COMPLIANCE REQUIRED • WEBSEC ENGINE V2.5",
            size="1",
            color="var(--muted)",
            font_family="DM Mono",
            text_align="center",
            margin_top="2rem",
        ),
        
        max_width="1000px",
        padding="2rem",
    )

# Custom CSS
app_style = """
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap');

:root {
    --bg: #07090f;
    --surface: #0d111c;
    --surface2: #151926;
    --border: #1e2540;
    --border2: #2a334f;
    --text: #e8ecf4;
    --text2: #9ba3be;
    --muted: #5a6480;
    --accent: #22C55E;
    --accent-bg: rgba(79,124,255,0.1);
    --red: #ff4d6d;
    --orange: #ffa94d;
    --yellow: #ffd54d;
    --green: #22c55e;
    --card-shadow: 0 8px 30px rgba(0,0,0,0.4);
}

body {
    font-family: 'Syne', sans-serif;
    background: var(--bg);
    color: var(--text);
}

.logo-box {
    width: 34px;
    height: 34px;
    background: var(--accent);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 18px;
    box-shadow: 0 4px 15px var(--accent-bg);
}

.logo-text {
    font-weight: 800;
    font-size: 1.2rem;
    letter-spacing: -0.02em;
}

.status-pill {
    background: var(--surface2);
    border: 1px solid var(--border);
    padding: 6px 14px;
    border-radius: 100px;
    font-size: 0.7rem;
    color: var(--text2);
}

.dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
}

.dot-idle { background: var(--green); }
.dot-scanning { background: var(--orange); animation: pulse 1s infinite; }

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.3; }
    100% { opacity: 1; }
}

.metrics-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
}

.m-card {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 1.5rem;
    border-radius: 16px;
    box-shadow: var(--card-shadow);
}

.m-label {
    color: var(--muted);
    font-size: 0.65rem;
    text-transform: uppercase;
    font-family: 'DM Mono', monospace;
    letter-spacing: 0.1em;
}

.m-val {
    font-size: 2.2rem;
    font-weight: 800;
    margin-top: 5px;
}

.detail-row {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border);
}

.detail-k {
    font-family: 'DM Mono', monospace;
    font-size: 0.7rem;
    color: var(--muted);
    font-weight: 700;
}

.detail-v {
    font-family: 'DM Mono', monospace;
    font-size: 0.85rem;
}
"""

# App configuration
app = rx.App(
    style=app_style,
    theme=rx.theme(
        appearance="dark",
        has_background=True,
        radius="large",
        accent_color="green",
    ),
)
app.add_page(index)
